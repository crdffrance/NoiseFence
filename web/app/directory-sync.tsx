import { useEffect, useState } from 'react';
import { CloudDownload, RefreshCw } from 'lucide-react';
import { api, type User } from './client';
import { ConfirmDialog } from './console-ui';
import { ScimEnrollment } from './directory-scim';
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
type SyncProvider =
  | 'entra'
  | 'okta'
  | 'google'
  | 'aws_identity_store'
  | 'active_directory';
export function adFormError(
  source: Source,
  domains: string[],
  publicKey: string,
) {
  const [domain, guid, extra] = source.authority.split(':');
  const host =
    (domain ?? '').length <= 253 &&
    (domain ?? '').includes('.') &&
    (domain ?? '')
      .split('.')
      .every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
  return source.provider !== 'active_directory'
    ? 'Choose an Active Directory source.'
    : sourceError({ ...source, provider: 'manual' }, domains) ||
        (!host ||
        extra !== undefined ||
        !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(guid ?? '') ||
        guid === '00000000-0000-0000-0000-000000000000'
          ? 'Enter the AD DNS domain and its objectGUID, separated by a colon.'
          : !/^B[A-P][A-Za-z0-9+/]{85}=$/.test(publicKey)
            ? 'Enter the 88-character base64 P-256 public key from the internal collector. Never upload the private key.'
            : null);
}
export function parseAdEnvelope(text: string) {
  if (new TextEncoder().encode(text).length > 23 * 1024 * 1024)
    throw new Error('Signed AD export exceeds 23 MiB.');
  const v = JSON.parse(text);
  if (
    !v ||
    typeof v !== 'object' ||
    Array.isArray(v) ||
    Object.keys(v).sort().join(',') !==
      'id,key_id,payload,protocol,signature' ||
    v.protocol !== 'noisefence-ad-export-1' ||
    typeof v.id !== 'string' ||
    !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(v.id) ||
    v.id === '00000000-0000-0000-0000-000000000000' ||
    typeof v.key_id !== 'string' ||
    !/^[0-9a-f]{64}$/.test(v.key_id) ||
    typeof v.payload !== 'string' ||
    typeof v.signature !== 'string'
  )
    throw new Error(
      'Select an unmodified signed export from the internal AD collector.',
    );
  return v as {
    protocol: string;
    id: string;
    key_id: string;
    payload: string;
    signature: string;
  };
}
export function awsFormError(
  source: Source,
  domains: string[],
  access: string,
  secret: string,
  token: string,
) {
  const regions = new Set(
    'us-east-1 us-east-2 us-west-1 us-west-2 af-south-1 ap-east-1 ap-east-2 ap-south-1 ap-south-2 ap-southeast-1 ap-southeast-2 ap-southeast-3 ap-southeast-4 ap-southeast-5 ap-southeast-6 ap-southeast-7 ap-northeast-1 ap-northeast-2 ap-northeast-3 ca-central-1 ca-west-1 eu-central-1 eu-central-2 eu-west-1 eu-west-2 eu-west-3 eu-north-1 eu-south-1 eu-south-2 il-central-1 mx-central-1 me-south-1 me-central-1 sa-east-1'.split(
      ' ',
    ),
  );
  const [region, store, extra] = source.authority.split(':');
  return source.provider !== 'aws_identity_store'
    ? 'Choose an AWS Identity Store source.'
    : sourceError({ ...source, provider: 'manual' }, domains) ||
        (!regions.has(region) ||
        extra !== undefined ||
        !/^(?:d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.test(
          store ?? '',
        ) ||
        store === '00000000-0000-0000-0000-000000000000'
          ? 'Enter a supported commercial AWS region and identity store ID, separated by a colon.'
          : !/^ASIA[A-Z0-9]{16}$/.test(access) ||
              !/^[A-Za-z0-9+/=._~-]{40}$/.test(secret) ||
              !/^[A-Za-z0-9+/=._~-]{1,8192}$/.test(token)
            ? 'Enter a temporary AWS access key ID, 40-character secret key and session token. Long-lived IAM keys are not supported.'
            : null);
}
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
  const [scimEdit, setScimEdit] = useState<SavedConnection | 'new' | null>(
    null,
  );
  const [scimBusy, setScimBusy] = useState(false);
  const [open, setOpen] = useState(false),
    [existing, setExisting] = useState(''),
    [provider, setProvider] = useState<SyncProvider>('entra'),
    [label, setLabel] = useState(''),
    [sourceId, setSourceId] = useState(''),
    [tenant, setTenant] = useState(''),
    [scopes, setScopes] = useState<string[]>(
      domains.length === 1 ? [...domains] : [],
    ),
    [client, setClient] = useState(''),
    [secret, setSecret] = useState(''),
    [sessionToken, setSessionToken] = useState(''),
    [adUpload, setAdUpload] = useState<SavedConnection | null>(null),
    [adFile, setAdFile] = useState<File | null>(null),
    [adFileEpoch, setAdFileEpoch] = useState(0),
    [fingerprintResult, setFingerprint] = useState({ key: '', value: '' }),
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
    (provider === 'active_directory'
      ? adFormError(source, domains, secret)
      : provider === 'entra'
        ? entraFormError(source, domains, client, secret)
        : provider === 'google'
          ? googleFormError(source, domains, secret)
          : provider === 'aws_identity_store'
            ? awsFormError(source, domains, client, secret, sessionToken)
            : oktaFormError(source, domains, secret)) ||
    (!selected && sources.some((s) => s.source.id === sourceId)
      ? 'This source ID already exists. Select the installed source or use a new ID.'
      : null);
  const fingerprint =
    provider === 'active_directory' && fingerprintResult.key === secret
      ? fingerprintResult.value
      : '';
  const saveProblem =
    problem ||
    connectionLifetimeError(provider, lifetime) ||
    (provider === 'active_directory' && !/^[0-9a-f]{64}$/.test(fingerprint)
      ? 'Wait for the public-key fingerprint before enrollment.'
      : null) ||
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
    sessionToken ||
    sourceId ||
    label ||
    tenant ||
    scheduleDraft ||
    adUpload
  );
  useEffect(() => {
    let current = true;
    if (
      provider === 'active_directory' &&
      /^B[A-P][A-Za-z0-9+/]{85}=$/.test(secret)
    ) {
      const data = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0));
      void crypto.subtle
        .digest('SHA-256', data)
        .then((hash) => {
          if (current)
            setFingerprint({
              key: secret,
              value: Array.from(new Uint8Array(hash), (b) =>
                b.toString(16).padStart(2, '0'),
              ).join(''),
            });
        })
        .catch(() => {
          if (current) setFingerprint({ key: secret, value: 'Unavailable' });
        });
    }
    return () => {
      current = false;
    };
  }, [provider, secret]);
  useEffect(() => {
    onDirty(dirty || scimEdit !== null);
    return () => onDirty(false);
  }, [dirty, scimEdit, onDirty]);
  useEffect(() => {
    onBusy(busy || scimBusy);
    return () => onBusy(false);
  }, [busy, scimBusy, onBusy]);
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
    setSessionToken('');
    setClient('');
    setSourceId('');
    setLabel('');
    setTenant('');
    setEditingAccess(null);
    setExisting('');
    setOpen(false);
    setRetain(provider === 'active_directory');
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
    if (disabled || busy || scimEdit !== null || scimBusy) return;
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
  async function uploadAd() {
    if (
      disabled ||
      busy ||
      scimEdit !== null ||
      scimBusy ||
      !adUpload ||
      !adFile
    )
      return;
    setBusy(true);
    setError('');
    try {
      if (adFile.size > 23 * 1024 * 1024)
        throw new Error('Signed AD export exceeds 23 MiB.');
      const envelope = parseAdEnvelope(await adFile.text());
      rememberJob(envelope.id);
      const result = await api<{ id: string }>(
        '/admin/identity/sync/active_directory',
        {
          revision,
          catalog_sha256: installed,
          connection: {
            source_id: adUpload.source.id,
            generation: adUpload.generation,
          },
          envelope,
        },
        user.csrf,
      );
      if (result.id !== envelope.id)
        throw new Error(
          'Unexpected collection receipt. Reload status before retrying.',
        );
      setAdUpload(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdFile(null);
      setAdFileEpoch((n) => n + 1);
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
    if (
      disabled ||
      busy ||
      scimEdit !== null ||
      scimBusy ||
      !scheduleDraft ||
      scheduleProblem
    )
      return;
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
    if (disabled || busy || scimEdit !== null || scimBusy || !confirmAccess)
      return;
    const action = confirmAccess;
    setBusy(true);
    setError('');
    const credential = secret;
    const temporaryToken = sessionToken;
    setSecret('');
    setSessionToken('');
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
              provider === 'active_directory'
                ? { kind: 'ad_collector_public_key', public_key: credential }
                : provider === 'entra'
                  ? {
                      kind: 'entra_application',
                      client_id: client,
                      client_secret: credential,
                    }
                  : provider === 'aws_identity_store'
                    ? {
                        kind: 'aws_session',
                        access_key_id: client,
                        secret_access_key: credential,
                        session_token: temporaryToken,
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
    if (
      disabled ||
      busy ||
      scimEdit !== null ||
      scimBusy ||
      problem ||
      provider === 'active_directory'
    )
      return;
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
    const temporaryToken = sessionToken;
    setSecret('');
    setSessionToken('');
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
            : provider === 'aws_identity_store'
              ? {
                  access_key_id: client,
                  secret_access_key: credential,
                  session_token: temporaryToken,
                }
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
            Collect identities from Microsoft Entra, Google Workspace, Okta or
            AWS Identity Store, or import a signed Active Directory export.
            Review every candidate before activation.
          </p>
        </div>
        <button
          type="button"
          className="secondary"
          disabled={disabled || busy || scimEdit !== null || scimBusy}
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
        <fieldset
          disabled={disabled || busy || scimEdit !== null || scimBusy}
          className="directory-sync-form"
        >
          <legend>Read-only connection</legend>
          <label>
            Provider
            <select
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value as SyncProvider);
                setExisting('');
                setEditingAccess(null);
                setLifetime(
                  ['entra', 'active_directory'].includes(e.target.value)
                    ? 1440
                    : 30,
                );
                setRetain(e.target.value === 'active_directory');
                setTenant('');
                setClient('');
                setSecret('');
                setSessionToken('');
              }}
            >
              <option value="active_directory">
                Active Directory — internal collector
              </option>
              <option value="entra">Microsoft Entra ID</option>
              <option value="google">Google Workspace</option>
              <option value="okta">Okta</option>
              <option value="aws_identity_store">
                AWS IAM Identity Center
              </option>
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
                  setSessionToken('');
                  setClient('');
                }}
              >
                <option value="">
                  New{' '}
                  {provider === 'active_directory'
                    ? 'Active Directory'
                    : provider === 'entra'
                      ? 'Entra'
                      : provider === 'google'
                        ? 'Google Workspace'
                        : provider === 'aws_identity_store'
                          ? 'AWS Identity Store'
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
                {provider === 'active_directory'
                  ? 'AD DNS domain:objectGUID'
                  : provider === 'entra'
                    ? 'Tenant ID'
                    : provider === 'google'
                      ? 'Google customer ID'
                      : provider === 'aws_identity_store'
                        ? 'AWS region:identity store ID'
                        : 'Okta org hostname'}
                <input
                  value={tenant}
                  maxLength={
                    provider === 'entra' ? 36 : provider === 'google' ? 64 : 256
                  }
                  placeholder={
                    provider === 'active_directory'
                      ? 'corp.example:11111111-1111-4111-8111-111111111111'
                      : provider === 'okta'
                        ? 'company.okta.com'
                        : provider === 'google'
                          ? 'C01234567'
                          : provider === 'aws_identity_store'
                            ? 'eu-west-3:d-1234567890'
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
          {(provider === 'entra' || provider === 'aws_identity_store') && (
            <label>
              {provider === 'entra'
                ? 'Application (client) ID'
                : 'Temporary AWS access key ID'}
              <input
                value={client}
                maxLength={36}
                autoComplete="off"
                onChange={(e) => setClient(e.target.value)}
              />
            </label>
          )}
          <label>
            {provider === 'active_directory'
              ? 'Collector public verification key (base64)'
              : provider === 'entra'
                ? 'Application secret'
                : provider === 'aws_identity_store'
                  ? 'AWS secret access key'
                  : 'OAuth access token'}
            <input
              type={provider === 'active_directory' ? 'text' : 'password'}
              value={secret}
              maxLength={
                provider === 'active_directory'
                  ? 88
                  : provider === 'entra'
                    ? 4096
                    : provider === 'aws_identity_store'
                      ? 40
                      : 8192
              }
              autoComplete="new-password"
              spellCheck={false}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          {provider === 'aws_identity_store' && (
            <label>
              AWS session token
              <input
                type="password"
                value={sessionToken}
                maxLength={8192}
                autoComplete="new-password"
                spellCheck={false}
                onChange={(e) => setSessionToken(e.target.value)}
              />
            </label>
          )}
          <p className="muted small">
            {provider === 'active_directory'
              ? 'Run the Windows collector inside your network using LDAPS and Kerberos. Enroll only its public P-256 key. NoiseFence never connects to LDAP. The DNS domain and domain objectGUID must match the local collector profile.'
              : provider === 'entra'
                ? 'The Entra administrator must grant User.Read.All and GroupMember.Read.All application permissions with tenant admin consent. No mailbox access is requested.'
                : provider === 'google'
                  ? 'Use a short-lived token with admin.directory.user.readonly, admin.directory.group.readonly and admin.directory.domain.readonly scopes. The administrator must have visibility of the intended directory. External and whole-customer memberships are reported as exclusions. No Gmail permission is requested.'
                  : provider === 'aws_identity_store'
                    ? 'Use temporary STS access with identitystore:ListUsers, identitystore:ListGroups and identitystore:ListGroupMemberships for this store. UserStatus is imported when supplied; absent status remains unknown. Login names, permission sets, group mail aliases and delegation are not inferred. No AWS account administration or mailbox access is requested.'
                    : 'Use an OAuth token with okta.users.read and okta.groups.read, and an admin role/resource set covering the intended directory. Login names and recovery addresses are not imported as aliases. Custom org domains and API tokens (SSWS) are not supported.'}
          </p>
          <label className="check">
            <input
              type="checkbox"
              disabled={provider === 'active_directory'}
              checked={retain}
              onChange={(e) => setRetain(e.target.checked)}
            />
            {provider === 'active_directory'
              ? 'Enroll this verification key for signed imports'
              : 'Store encrypted access for reuse'}
          </label>
          {retain && (
            <>
              <label>
                Access lifetime (minutes)
                <input
                  type="number"
                  min={1}
                  max={
                    ['entra', 'active_directory'].includes(provider)
                      ? 129600
                      : 60
                  }
                  step={1}
                  value={lifetime}
                  onChange={(e) => setLifetime(Number(e.target.value))}
                />
              </label>
              <p className="notice">
                Stored only on the management server, bound to this source and
                your administrator account version. Maximum{' '}
                {['entra', 'active_directory'].includes(provider)
                  ? '90 days'
                  : 'one hour'}
                ; an earlier provider expiry still applies. This does not enable
                scheduled collection.
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
                ? provider === 'active_directory'
                  ? 'Review verification key'
                  : 'Review encrypted access'
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
      {adUpload && (
        <fieldset
          className="directory-sync-form"
          disabled={disabled || busy || scimEdit !== null || scimBusy}
        >
          <legend>Upload signed Active Directory export</legend>
          <p>
            <strong>{adUpload.source.label}</strong> ·{' '}
            {adUpload.source.authority}
          </p>
          <p className="notice">
            Choose the complete export produced by your internal collector
            within the last 15 minutes. The server verifies the enrolled key,
            source, freshness and completeness. Existing identities stay active
            until you review and apply the candidate.
          </p>
          <label>
            Signed export (.json)
            <input
              key={adFileEpoch}
              type="file"
              accept=".json,application/json"
              onChange={(e) => setAdFile(e.target.files?.[0] ?? null)}
            />
          </label>
          {adFile && (
            <p className="small">
              {adFile.name} · {(adFile.size / 1024).toFixed(1)} KiB
            </p>
          )}
          <div className="actions">
            <button
              type="button"
              disabled={!adFile || adFile.size > 23 * 1024 * 1024}
              onClick={() => void uploadAd()}
            >
              Verify and prepare candidate
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setAdUpload(null);
                setAdFile(null);
              }}
            >
              Cancel upload
            </button>
          </div>
        </fieldset>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={
            disabled ||
            busy ||
            dirty ||
            scimEdit !== null ||
            !saved ||
            !['ready', 'not_initialized'].includes(saved.vault) ||
            saved.connections.length >= 16
          }
          onClick={() => setScimEdit('new')}
        >
          Set up SCIM provisioning
        </button>
      </div>
      {(visible || scimBusy) && scimEdit !== null && (
        <ScimEnrollment
          user={user}
          revision={revision}
          installed={installed}
          domains={domains}
          existing={scimEdit === 'new' ? null : scimEdit}
          disabled={disabled || busy || dirty}
          onBusy={setScimBusy}
          onClose={() => {
            setScimEdit(null);
            setAttempt((v) => v + 1);
          }}
          onChanged={() => setAttempt((v) => v + 1)}
        />
      )}
      <SavedConnections
        username={user.username}
        onSchedule={editSchedule}
        onStopSchedule={(entry) => editSchedule(entry, true)}
        onInspect={rememberJob}
        value={saved}
        busy={disabled || busy || scimEdit !== null || scimBusy || dirty}
        onCollect={(entry) =>
          entry.source.provider === 'active_directory'
            ? setAdUpload(entry)
            : void startSaved(entry)
        }
        onReplace={(entry) => {
          if (entry.source.provider === 'scim') {
            setScimEdit(entry);
            return;
          }
          setEditingAccess(entry);
          setExisting('');
          setProvider(entry.source.provider as SyncProvider);
          setClient('');
          setSecret('');
          setSessionToken('');
          setSourceId('');
          setLabel('');
          setTenant('');
          setRetain(true);
          setLifetime(
            ['entra', 'active_directory'].includes(entry.source.provider)
              ? 1440
              : 30,
          );
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
              ? provider === 'active_directory'
                ? 'Enroll AD verification key?'
                : 'Store encrypted directory access?'
              : 'Revoke directory access?'
          }
          confirmLabel={
            confirmAccess === 'save'
              ? provider === 'active_directory'
                ? 'Enroll public key'
                : 'Save encrypted access'
              : 'Revoke access'
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
              {provider === 'active_directory' && (
                <p className="notice">
                  Verify this SHA-256 fingerprint against the internal collector
                  before enrollment:{' '}
                  <code className="directory-key-fingerprint">
                    {fingerprint || 'Computing…'}
                  </code>
                  A signed export is still subject to candidate review. No
                  private key or LDAP credential is stored here.
                </p>
              )}
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
                disabled={disabled || busy || scimEdit !== null || scimBusy}
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
