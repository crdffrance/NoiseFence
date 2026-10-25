import { useEffect, useState } from 'react';
import { CloudDownload, RefreshCw } from 'lucide-react';
import { api, type User } from './client';
import { ConfirmDialog } from './console-ui';
import {
  SavedConnections,
  connectionLifetimeError,
  scheduleError,
  type ConnectionsView,
  type SavedConnection,
} from './directory-connections';
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
      'Collection authorization is no longer valid. Check the administrator session, stored access and any scheduled grant.',
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
export function googleFormError(
  source: Source,
  domains: string[],
  token: string,
) {
  return source.provider !== 'google'
    ? 'Choose a Google Workspace source.'
    : sourceError({ ...source, provider: 'manual' }, domains) ||
        (!/^C[A-Za-z0-9]{1,63}$/.test(source.authority)
          ? 'Enter the immutable Google customer ID, beginning with C. Do not use my_customer.'
          : !/^[A-Za-z0-9._~+/=-]{1,8192}$/.test(token)
            ? 'Enter a scoped OAuth access token of at most 8 KiB, without the Bearer prefix.'
            : null);
}
export function CollectionCoverage({
  value,
}: {
  value: DirectoryPrepared['collection'];
}) {
  if (!value) return null;
  const labels: Record<string, string> = {
    device: 'Devices',
    servicePrincipal: 'Service principals',
    orgContact: 'Organization contacts',
    external_membership: 'External group members',
    customer_wide_membership: 'Whole-customer memberships',
    inactive_or_unknown_membership: 'Inactive or unknown-status memberships',
  };
  const excluded = Object.entries(value.excluded_members);
  return (
    <section aria-label="Collection coverage">
      <h4>Collection coverage</h4>
      <p className="small muted">
        {value.pages} pages · {value.requests} requests ·{' '}
        {Math.ceil(value.bytes / 1024)} KiB received
      </p>
      {excluded.length > 0 ? (
        <>
          <p className="directory-attention">
            Some membership entries are not represented in this directory.
            Review these exclusions before applying the candidate.
          </p>
          <dl>
            {excluded.map(([kind, count]) => (
              <div key={kind}>
                <dt>{labels[kind] ?? 'Other excluded memberships'}</dt>
                <dd>{count}</dd>
              </div>
            ))}
          </dl>
        </>
      ) : (
        <p className="small muted">
          No membership entries were excluded by the collector. Provider
          permissions still determine which records are visible.
        </p>
      )}
    </section>
  );
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
    [provider, setProvider] = useState<'entra' | 'okta' | 'google'>('entra'),
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
    [pollError, setPollError] = useState(''),
    [job, setJob] = useState<SyncStatus | null>(null),
    [attempt, setAttempt] = useState(0),
    [saved, setSaved] = useState<ConnectionsView | null>(null),
    [savedError, setSavedError] = useState(''),
    [scheduleDraft, setScheduleDraft] = useState<{
      entry: SavedConnection;
      stop: boolean;
      minutes: number;
      expires: string;
    } | null>(null),
    [scheduleReceipt, setScheduleReceipt] = useState(''),
    [editingAccess, setEditingAccess] = useState<SavedConnection | null>(null),
    [retain, setRetain] = useState(false),
    [lifetime, setLifetime] = useState(1440),
    [confirmAccess, setConfirmAccess] = useState<
      'save' | SavedConnection | null
    >(null),
    [saveReceipt, setSaveReceipt] = useState(() => {
      try {
        const value =
          sessionStorage.getItem(
            `noisefence-directory-access:${user.username}`,
          ) ?? '';
        return uuid.test(value) ? value : '';
      } catch {
        return '';
      }
    });
  const [jobId, setJobId] = useState(() => {
    try {
      const value = sessionStorage.getItem(storageKey) ?? '';
      return uuid.test(value) ? value : '';
    } catch {
      return '';
    }
  });
  const selected =
    editingAccess ??
    sources.find(
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
      : provider === 'google'
        ? googleFormError(source, domains, secret)
        : oktaFormError(source, domains, secret)) ||
    (!selected && sources.some((s) => s.source.id === sourceId)
      ? 'This source ID already exists. Select the installed source or use a new ID.'
      : null);
  const saveProblem =
    problem ||
    connectionLifetimeError(provider, lifetime) ||
    (!saved
      ? 'Reload saved access before saving.'
      : !editingAccess &&
          saved.connections.some((c) => c.source.id === source.id)
        ? 'Saved access already exists for this ID. Use Replace access below.'
        : null);
  const scheduleEnd = scheduleDraft
    ? Math.floor(new Date(scheduleDraft.expires).getTime() / 1000)
    : 0;
  const scheduleProblem =
    scheduleDraft && !scheduleDraft.stop
      ? scheduleError(
          scheduleDraft.entry,
          user.username,
          scheduleDraft.minutes,
          scheduleEnd,
        )
      : null;
  const dirty = !!(
    client ||
    secret ||
    sourceId ||
    label ||
    tenant ||
    scheduleDraft
  );
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
        setPollError('');
        if (next.state === 'running')
          timer = setTimeout(() => void poll(), 3000);
      } catch (e) {
        if (!abort.signal.aborted) setPollError((e as Error).message);
      }
    }
    void poll();
    return () => {
      abort.abort();
      if (timer) clearTimeout(timer);
    };
  }, [jobId, attempt, visible, revision, busy]);
  useEffect(() => {
    if (!visible || busy) return;
    const abort = new AbortController();
    void api<ConnectionsView>(
      '/admin/identity/connections',
      undefined,
      undefined,
      { signal: abort.signal, cache: 'no-store' },
    )
      .then((value) => {
        if (!abort.signal.aborted) {
          setSaved(value);
          setSavedError('');
        }
      })
      .catch((e: Error) => {
        if (!abort.signal.aborted) {
          setSaved(null);
          setSavedError(e.message);
        }
      });
    return () => abort.abort();
  }, [visible, busy, revision, attempt, user.username]);
  function clearForm() {
    setSecret('');
    setClient('');
    setSourceId('');
    setLabel('');
    setTenant('');
    setEditingAccess(null);
    setExisting('');
    setOpen(false);
    setRetain(false);
  }
  function rememberJob(operation: string) {
    setJobId(operation);
    setJob(null);
    setPollError('');
    try {
      sessionStorage.setItem(storageKey, operation);
    } catch {
      /* Receipt only. */
    }
  }
  async function startSaved(entry: SavedConnection) {
    if (disabled || busy) return;
    setBusy(true);
    setError('');
    const operation = crypto.randomUUID();
    rememberJob(operation);
    try {
      await api(
        '/admin/identity/sync/stored',
        {
          operation,
          revision,
          catalog_sha256: installed,
          connection: {
            source_id: entry.source.id,
            generation: entry.generation,
          },
        },
        user.csrf,
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function editSchedule(entry: SavedConnection, stop = false) {
    const end = new Date(
      Math.min(entry.expires, Math.floor(Date.now() / 1000) + 86400) * 1000,
    );
    // datetime-local displays local time; the submitted value is an epoch timestamp.
    const local = new Date(end.getTime() - end.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16);
    setScheduleDraft({
      entry,
      stop,
      minutes: entry.schedule?.interval_seconds
        ? entry.schedule.interval_seconds / 60
        : 60,
      expires: local,
    });
  }
  async function mutateSchedule() {
    if (disabled || busy || !scheduleDraft || scheduleProblem) return;
    const draft = scheduleDraft,
      operation = crypto.randomUUID();
    setBusy(true);
    setError('');
    if (!draft.stop) setScheduleReceipt(operation);
    try {
      const connection = {
        source_id: draft.entry.source.id,
        generation: draft.entry.generation,
      };
      setSaved(
        await api<ConnectionsView>(
          draft.stop
            ? '/admin/identity/schedules/stop'
            : '/admin/identity/schedules',
          draft.stop
            ? { connection, expected_grant: draft.entry.schedule?.id }
            : {
                operation,
                revision,
                catalog_sha256: installed,
                connection,
                expected_grant: draft.entry.schedule?.id ?? null,
                interval_seconds: draft.minutes * 60,
                expires: scheduleEnd,
              },
          user.csrf,
        ),
      );
    } catch (e) {
      setError(
        `${(e as Error).message} Reload saved access to check the schedule before another attempt.`,
      );
    } finally {
      setScheduleDraft(null);
      setBusy(false);
    }
  }
  async function mutateAccess() {
    if (disabled || busy || !confirmAccess) return;
    const action = confirmAccess;
    setBusy(true);
    setError('');
    const credential = secret;
    setSecret('');
    try {
      if (action === 'save') {
        if (saveProblem) throw new Error(saveProblem);
        const operation = crypto.randomUUID();
        setSaveReceipt(operation);
        try {
          sessionStorage.setItem(
            `noisefence-directory-access:${user.username}`,
            operation,
          );
        } catch {
          /* UUID only, no secret. */
        }
        const value = await api<ConnectionsView>(
          '/admin/identity/connections',
          {
            operation,
            revision,
            catalog_sha256: installed,
            expected_generation: editingAccess?.generation ?? null,
            source,
            expires: Math.floor(Date.now() / 1000) + lifetime * 60,
            credential:
              provider === 'entra'
                ? {
                    kind: 'entra_application',
                    client_id: client,
                    client_secret: credential,
                  }
                : {
                    kind:
                      provider === 'google'
                        ? 'google_access_token'
                        : 'okta_access_token',
                    access_token: credential,
                  },
          },
          user.csrf,
        );
        setSaved(value);
        clearForm();
      } else {
        setSaved(
          await api<ConnectionsView>(
            '/admin/identity/connections/revoke',
            { source_id: action.source.id, generation: action.generation },
            user.csrf,
          ),
        );
        if (editingAccess?.source.id === action.source.id) clearForm();
      }
    } catch (e) {
      setError(
        `${(e as Error).message} Check saved access before another attempt.`,
      );
    } finally {
      setConfirmAccess(null);
      setBusy(false);
    }
  }
  async function start() {
    if (disabled || busy || problem) return;
    setBusy(true);
    setError('');
    const operation = crypto.randomUUID();
    setJobId(operation);
    setJob(null);
    setPollError('');
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
      clearForm();
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
            Collect identities from Microsoft Entra, Google Workspace or Okta.
            Review every candidate before activation.
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
        Each action starts a one-time collection. By default the credential is
        request-only and is not saved in settings, history or browser storage.
        You can explicitly store encrypted access for reuse. Scheduled
        collection requires a separate, expiring authorization below.
      </p>
      {open && (
        <fieldset disabled={disabled || busy} className="directory-sync-form">
          <legend>Read-only connection</legend>
          <label>
            Provider
            <select
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value as 'entra' | 'okta' | 'google');
                setExisting('');
                setEditingAccess(null);
                setLifetime(e.target.value === 'entra' ? 1440 : 30);
                setTenant('');
                setClient('');
                setSecret('');
              }}
            >
              <option value="entra">Microsoft Entra ID</option>
              <option value="google">Google Workspace</option>
              <option value="okta">Okta</option>
            </select>
          </label>
          {!editingAccess && (
            <label>
              Source
              <select
                value={existing}
                onChange={(e) => {
                  setExisting(e.target.value);
                  setEditingAccess(null);
                  setSecret('');
                  setClient('');
                }}
              >
                <option value="">
                  New{' '}
                  {provider === 'entra'
                    ? 'Entra'
                    : provider === 'google'
                      ? 'Google Workspace'
                      : 'Okta'}{' '}
                  source
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
          )}
          {editingAccess && (
            <p className="notice">
              Replacing stored access for {editingAccess.source.label}. The
              source and authority remain fixed.
            </p>
          )}
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
                {provider === 'entra'
                  ? 'Tenant ID'
                  : provider === 'google'
                    ? 'Google customer ID'
                    : 'Okta org hostname'}
                <input
                  value={tenant}
                  maxLength={
                    provider === 'entra' ? 36 : provider === 'google' ? 64 : 256
                  }
                  placeholder={
                    provider === 'okta'
                      ? 'company.okta.com'
                      : provider === 'google'
                        ? 'C01234567'
                        : undefined
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
              : provider === 'google'
                ? 'Use a short-lived token with admin.directory.user.readonly, admin.directory.group.readonly and admin.directory.domain.readonly scopes. The administrator must have visibility of the intended directory. External and whole-customer memberships are reported as exclusions. No Gmail permission is requested.'
                : 'Use an OAuth token with okta.users.read and okta.groups.read, and an admin role/resource set covering the intended directory. Login names and recovery addresses are not imported as aliases. Custom org domains and API tokens (SSWS) are not supported.'}
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={retain}
              onChange={(e) => setRetain(e.target.checked)}
            />
            Store encrypted access for reuse
          </label>
          {retain && (
            <>
              <label>
                Access lifetime (minutes)
                <input
                  type="number"
                  min={1}
                  max={provider === 'entra' ? 129600 : 60}
                  step={1}
                  value={lifetime}
                  onChange={(e) => setLifetime(Number(e.target.value))}
                />
              </label>
              <p className="notice">
                Stored only on the management server, bound to this source and
                your administrator account version. Maximum{' '}
                {provider === 'entra' ? '90 days' : 'one hour'}; an earlier
                provider expiry still applies. This does not enable scheduled
                collection.
              </p>
            </>
          )}
          {(retain ? saveProblem : problem) && (
            <p className="muted small">{retain ? saveProblem : problem}</p>
          )}
          <button
            type="button"
            disabled={!!(retain ? saveProblem : problem)}
            onClick={() => (retain ? setConfirmAccess('save') : void start())}
          >
            {busy
              ? 'Working…'
              : retain
                ? 'Review encrypted access'
                : 'Start read-only collection'}
          </button>
          <button type="button" className="secondary" onClick={clearForm}>
            Discard connection draft
          </button>
        </fieldset>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => setAttempt((n) => n + 1)}
        >
          <RefreshCw size={14} />
          Reload saved access
        </button>
      </div>
      {savedError && (
        <p className="alert error" role="alert">
          {savedError}
        </p>
      )}
      {saveReceipt && (
        <output className="notice directory-access-receipt">
          {saved?.connections.some((c) => c.generation === saveReceipt)
            ? 'Saved generation confirmed.'
            : 'Save outcome not confirmed in the current list. Reload and inspect saved access before another attempt.'}{' '}
          <code>{saveReceipt}</code>
        </output>
      )}
      {scheduleReceipt && (
        <output className="notice directory-access-receipt">
          {saved?.connections.some((c) => c.schedule?.id === scheduleReceipt)
            ? 'Schedule authorization recorded. Check the collection status below; this does not confirm provider access or activate a candidate.'
            : 'Schedule outcome not confirmed. Reload saved access before another attempt.'}{' '}
          <code>{scheduleReceipt}</code>
        </output>
      )}
      <SavedConnections
        username={user.username}
        onSchedule={editSchedule}
        onStopSchedule={(entry) => editSchedule(entry, true)}
        onInspect={rememberJob}
        value={saved}
        busy={disabled || busy || dirty}
        onCollect={(entry) => void startSaved(entry)}
        onReplace={(entry) => {
          setEditingAccess(entry);
          setExisting('');
          setProvider(entry.source.provider as 'entra' | 'okta' | 'google');
          setClient('');
          setSecret('');
          setSourceId('');
          setLabel('');
          setTenant('');
          setRetain(true);
          setLifetime(entry.source.provider === 'entra' ? 1440 : 30);
          setOpen(true);
        }}
        onRevoke={setConfirmAccess}
      />
      {scheduleDraft && (
        <ConfirmDialog
          title={
            scheduleDraft.stop
              ? 'Stop automatic collection?'
              : 'Authorize automatic collection?'
          }
          confirmLabel={
            scheduleDraft.stop ? 'Stop collection' : 'Authorize schedule'
          }
          danger={scheduleDraft.stop}
          busy={busy}
          confirmDisabled={disabled || !!scheduleProblem}
          onCancel={() => setScheduleDraft(null)}
          onConfirm={() => void mutateSchedule()}
        >
          <p>
            <strong>{scheduleDraft.entry.source.label}</strong> ·{' '}
            {scheduleDraft.entry.source.authority}
          </p>
          {scheduleDraft.stop ? (
            <p>
              New scheduled reads will stop. An active collection is cancelled
              at its next authorization check; transmitted requests cannot be
              recalled. Stored access and installed snapshots remain available.
            </p>
          ) : (
            <>
              <p>
                The management service may read this directory after you sign
                out, until the authorization expires or is stopped. Only the
                stored source and domains are covered. Changing the credential
                or the owner’s account authorization stops this grant.
              </p>
              <fieldset disabled={busy} className="directory-schedule-fields">
                <label>
                  Collection interval (minutes)
                  <input
                    type="number"
                    min={15}
                    max={1440}
                    step={1}
                    value={scheduleDraft.minutes}
                    onChange={(e) =>
                      setScheduleDraft({
                        ...scheduleDraft,
                        minutes: Number(e.target.value),
                      })
                    }
                  />
                </label>
                <label>
                  Authorization ends (local time)
                  <input
                    type="datetime-local"
                    value={scheduleDraft.expires}
                    onChange={(e) =>
                      setScheduleDraft({
                        ...scheduleDraft,
                        expires: e.target.value,
                      })
                    }
                  />
                </label>
              </fieldset>
              <p className="notice">
                First collection may start within 30 seconds. Each completed
                candidate waits for review and policy activation. Failures delay
                retries; no snapshot is activated automatically.
              </p>
              <p className="small muted">
                Stored access expires{' '}
                {new Date(scheduleDraft.entry.expires * 1000).toLocaleString(
                  'en-GB',
                )}
                . Provider expiry may be earlier; tokens are not refreshed
                automatically.
              </p>
              {scheduleProblem && <p className="error">{scheduleProblem}</p>}
            </>
          )}
        </ConfirmDialog>
      )}
      {confirmAccess && (
        <ConfirmDialog
          title={
            confirmAccess === 'save'
              ? 'Store encrypted directory access?'
              : 'Revoke directory access?'
          }
          confirmLabel={
            confirmAccess === 'save' ? 'Save encrypted access' : 'Revoke access'
          }
          danger={confirmAccess !== 'save'}
          busy={busy}
          confirmDisabled={
            disabled || (confirmAccess === 'save' && !!saveProblem)
          }
          onCancel={() => setConfirmAccess(null)}
          onConfirm={() => void mutateAccess()}
        >
          <p>
            <strong>
              {confirmAccess === 'save'
                ? source.label
                : confirmAccess.source.label}
            </strong>{' '}
            ·{' '}
            {confirmAccess === 'save'
              ? source.authority
              : confirmAccess.source.authority}
          </p>
          {confirmAccess === 'save' ? (
            <>
              <p>Receiving domains: {source.scopes.join(', ')}.</p>
              <p>
                The credential will be encrypted and stored for at most{' '}
                {lifetime.toLocaleString('en-US')} minutes.{' '}
                {editingAccess
                  ? 'This replaces the currently displayed generation.'
                  : 'This creates a saved connection.'}{' '}
                No collection or policy activation starts automatically.
              </p>
            </>
          ) : (
            <p>
              This blocks new collections and cancels an active collection when
              its next authorization check fails. Already transmitted requests
              cannot be recalled. Installed directory snapshots are retained;
              revoke the secret at the provider too if it was compromised.
            </p>
          )}
        </ConfirmDialog>
      )}
      {pollError && (
        <p className="error" role="alert">
          {pollError}
        </p>
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
              : pollError || error
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
