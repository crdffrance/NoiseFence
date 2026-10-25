import { useEffect, useId, useRef, useState } from 'react';
import { DirectorySync } from './directory-sync';
import {
  Building2,
  Users,
  UsersRound,
  ShieldCheck,
  Plus,
  Search,
  Upload,
  RefreshCw,
  ArrowRight,
  Trash2,
  Pencil,
  Check,
  Clock3,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import { ConfirmDialog, SectionTabs } from './console-ui';
import {
  addressList,
  directoryPending,
  identityError,
  MAX_PEOPLE_CSV_BYTES,
  mergePeople,
  newDirectory,
  parsePeopleCsv,
  preparedMatches,
  removeGroup,
  removePerson,
  roles,
  sourceError,
  type Activity,
  type DirectoryDraft,
  type DirectoryEdit,
  type DirectoryPrepared,
  type DirectorySelection,
  type DirectoryView,
  type Group,
  type Person,
} from './directory';

type ObjectEdit =
  | { kind: 'person'; original: string | null; value: Person }
  | { kind: 'group'; original: string | null; value: Group };
type Deletion = {
  kind: 'person' | 'group' | 'source';
  id: string;
  label: string;
};
const emptyPerson = (): Person => ({
  id: '',
  display_name: '',
  kind: 'person',
  activity: 'active',
  addresses: [],
  protected_roles: [],
});
const emptyGroup = (): Group => ({
  id: '',
  display_name: '',
  activity: 'active',
  addresses: [],
  protected: false,
});
const stamp = (seconds: number) =>
  new Date(seconds * 1000).toLocaleString('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

export function DirectorySettings({
  user,
  revision,
  installed,
  selection,
  domains,
  onChange,
  visible,
  disabled,
  onDirty,
  onBusy,
}: {
  user: User;
  revision: number;
  installed: DirectorySelection | null | undefined;
  selection: DirectorySelection | null | undefined;
  domains: string[];
  onChange: (value: DirectorySelection | null) => void;
  visible: boolean;
  disabled: boolean;
  onDirty: (value: boolean) => void;
  onBusy: (value: boolean) => void;
}) {
  const id = useId(),
    sequence = useRef(0),
    file = useRef<HTMLInputElement>(null);
  const [view, setView] = useState<DirectoryView | null>(null),
    [reload, setReload] = useState(0),
    [localLoading, setLoading] = useState(false),
    [status, setStatus] = useState<{ key: string; error: string } | null>(null),
    [busy, setBusy] = useState(false),
    [syncBusy, setSyncBusy] = useState(false),
    [syncDirty, setSyncDirty] = useState(false),
    [error, setError] = useState(''),
    [notice, setNotice] = useState('');
  const [draft, setDraft] = useState<DirectoryDraft | null>(null),
    [original, setOriginal] = useState(''),
    [loadedSourceId, setLoadedSourceId] = useState<string | null>(null),
    [tab, setTab] = useState('people'),
    [query, setQuery] = useState(''),
    [page, setPage] = useState(0);
  const [editing, setEditing] = useState<ObjectEdit | null>(null),
    [deletion, setDeletion] = useState<Deletion | null>(null),
    [prepared, setPrepared] = useState<DirectoryPrepared | null>(null),
    [imported, setImported] = useState<Person[] | null>(null),
    [switchTo, setSwitchTo] = useState<string | null>(null),
    [discardLocal, setDiscardLocal] = useState(false);
  const [memberKind, setMemberKind] = useState<'person' | 'group'>('person'),
    [memberId, setMemberId] = useState(''),
    [groupId, setGroupId] = useState(''),
    [owner, setOwner] = useState(''),
    [delegate, setDelegate] = useState(''),
    [delegatedAddress, setDelegatedAddress] = useState('');
  const installedHash = installed?.sha256 ?? null;
  const statusKey = `${revision}:${installedHash}:${reload}`;
  const loading = localLoading || (visible && status?.key !== statusKey);
  const statusError = status?.key === statusKey ? status.error : '';
  const pending = directoryPending(selection, installedHash);
  const stale =
    !!view &&
    (view.revision !== revision || view.catalog_sha256 !== installedHash);
  const dirty = !!draft && JSON.stringify(draft) !== original;
  const unfinished =
    !pending && (dirty || editing !== null || imported !== null);
  useEffect(() => {
    onDirty(unfinished || syncDirty);
    return () => onDirty(false);
  }, [unfinished, syncDirty, onDirty]);
  useEffect(() => {
    onBusy(busy || syncBusy);
    return () => onBusy(false);
  }, [busy, syncBusy, onBusy]);
  const manual = draft?.source.provider === 'manual';
  const locked =
    disabled ||
    busy ||
    syncBusy ||
    loading ||
    pending ||
    stale ||
    !!statusError;
  const selectedSource = view?.sources.find(
    (s) => s.source.id === loadedSourceId,
  );
  const update = (next: DirectoryDraft) => {
    setDraft(next);
    setPrepared(null);
    setNotice('');
  };
  useEffect(() => {
    if (!visible) return;
    const controller = new AbortController();
    api<DirectoryView>('/admin/identity', undefined, undefined, {
      signal: controller.signal,
      cache: 'no-store',
    })
      .then((value) => {
        if (controller.signal.aborted) return;
        setView(value);
        setStatus({ key: statusKey, error: '' });
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setStatus({ key: statusKey, error: e.message });
      });
    return () => controller.abort();
  }, [visible, statusKey]);
  useEffect(
    () => () => {
      sequence.current++;
    },
    [],
  );
  async function loadSource(source: string) {
    const request = ++sequence.current;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      if (source === '') {
        const next = newDirectory(domains);
        setDraft(next);
        setOriginal('');
        setLoadedSourceId(null);
        setTab('source');
      } else {
        const next = await api<DirectoryView>(
          `/admin/identity?source=${encodeURIComponent(source)}`,
          undefined,
          undefined,
          { cache: 'no-store' },
        );
        if (request !== sequence.current) return;
        if (next.revision !== revision || next.catalog_sha256 !== installedHash)
          throw new Error(
            'The installed directory changed. Reload settings before continuing.',
          );
        setView(next);
        setDraft(next.draft);
        setOriginal(JSON.stringify(next.draft));
        setLoadedSourceId(source);
        setTab('people');
      }
      setQuery('');
      setPage(0);
      setGroupId('');
      setMemberId('');
      setOwner('');
      setDelegate('');
      setDelegatedAddress('');
      setPrepared(null);
      setEditing(null);
      setImported(null);
    } catch (e) {
      if (request === sequence.current) setError((e as Error).message);
    } finally {
      if (request === sequence.current) setLoading(false);
    }
  }
  function openSource(source: string) {
    if (dirty) setSwitchTo(source);
    else void loadSource(source);
  }
  async function prepare(edit: DirectoryEdit) {
    if (!view || locked) return;
    const request = ++sequence.current;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<DirectoryPrepared>(
        '/admin/identity/prepare',
        { revision, catalog_sha256: installedHash, edit },
        user.csrf,
      );
      if (request !== sequence.current) return;
      if (!preparedMatches(result, revision, installedHash))
        throw new Error(
          'The preparation no longer matches this configuration. Reload and review again.',
        );
      setPrepared(result);
    } catch (e) {
      if (request === sequence.current) setError((e as Error).message);
    } finally {
      if (request === sequence.current) setBusy(false);
    }
  }
  async function readCsv(selected?: File) {
    if (!selected) return;
    const request = ++sequence.current;
    setBusy(true);
    setError('');
    try {
      if (selected.size > MAX_PEOPLE_CSV_BYTES)
        throw new Error('People CSV must be at most 4 MiB.');
      const people = parsePeopleCsv(
        new TextDecoder('utf-8', { fatal: true }).decode(
          await selected.arrayBuffer(),
        ),
      );
      if (request === sequence.current) setImported(people);
    } catch (e) {
      if (request === sequence.current) setError((e as Error).message);
    } finally {
      if (request === sequence.current) setBusy(false);
    }
  }
  function template() {
    const url = URL.createObjectURL(
      new Blob(
        [
          'id,name,addresses,kind,activity,roles\r\nfinance-001,Alex Morgan,alex@example.test;finance@example.test,person,active,finance\r\n',
        ],
        { type: 'text/csv;charset=utf-8' },
      ),
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = 'noisefence-directory-people.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  let importPreview: ReturnType<typeof mergePeople> | null = null,
    importError = '';
  if (imported && draft) {
    try {
      importPreview = mergePeople(draft.people, imported);
    } catch (e) {
      importError = (e as Error).message;
    }
  }
  const editError = editing
    ? identityError(editing.value) ||
      (draft &&
      (editing.kind === 'person' ? draft.people : draft.groups).some(
        (p) => p.id === editing.value.id && p.id !== editing.original,
      )
        ? 'This ID is already assigned.'
        : null)
    : null;
  const sourceProblem =
    draft && manual
      ? sourceError(draft.source, domains) ||
        (!loadedSourceId &&
        view?.sources.some((s) => s.source.id === draft.source.id)
          ? 'This source ID already exists. Choose a new ID or edit the installed source.'
          : null)
      : null;
  const objects = draft ? (tab === 'groups' ? draft.groups : draft.people) : [];
  const matches = objects.filter((p) =>
    `${p.id} ${p.display_name} ${p.addresses.join(' ')}`
      .toLowerCase()
      .includes(query.trim().toLowerCase()),
  );
  const actualPage = Math.min(
    page,
    Math.max(0, Math.ceil(matches.length / 25) - 1),
  );
  const currentMembers = groupId
    ? (draft?.memberships.filter((m) => m.group === groupId) ?? [])
    : [];
  const ownerPerson = draft?.people.find((p) => p.id === owner);
  return (
    <section className="directory-workspace" aria-labelledby={`${id}-title`}>
      <header className="identity-intro">
        <span className="directory-emblem">
          <Building2 size={27} aria-hidden="true" />
        </span>
        <div>
          <p className="eyebrow">ORGANIZATION CONTEXT</p>
          <h2 id={`${id}-title`}>Identity directory</h2>
          <p>
            Give sender checks the context of your people, teams and trusted
            assignments.
          </p>
        </div>
        <span className="identity-badge">Observation only</span>
      </header>
      <div className="directory-steps" aria-label="Directory change workflow">
        <span>
          <b>1</b> Edit a source
        </span>
        <span>
          <b>2</b> Review its changes
        </span>
        <span>
          <b>3</b> Apply the policy
        </span>
      </div>
      <p className="small muted">
        Directory observations explain possible impersonation. They do not
        change message scores, delivery, accounts or accepted recipients.
      </p>
      {(error || statusError) && (
        <div className="alert error" role="alert">
          {error || statusError}{' '}
          <Button
            variant="outline"
            size="sm"
            disabled={busy || loading}
            onClick={() => setReload((n) => n + 1)}
          >
            Retry directory status
          </Button>
        </div>
      )}
      {notice && (
        <p className="notice" aria-live="polite">
          {notice}
        </p>
      )}
      {stale && (
        <p className="alert error" role="alert">
          The directory belongs to another configuration revision. Reload the
          installed settings using the page controls before editing.
        </p>
      )}
      {pending && (
        <div className="directory-pending" aria-live="polite">
          <ShieldCheck size={20} />
          <div>
            <strong>Directory change added to the policy draft</strong>
            <p>
              Use “Review and apply” below to activate it. Apply or discard that
              draft before preparing another source.
            </p>
            <code>{selection?.sha256 ?? 'Directory disabled'}</code>
          </div>
        </div>
      )}
      <DirectorySync
        user={user}
        revision={revision}
        installed={installedHash}
        domains={domains}
        sources={view?.sources ?? []}
        disabled={locked || unfinished}
        visible={visible}
        onPrepared={setPrepared}
        onDirty={setSyncDirty}
        onBusy={setSyncBusy}
      />
      <div className="directory-layout">
        <aside
          className="directory-sources"
          aria-label="Installed directory sources"
        >
          <div className="directory-heading">
            <h3>
              Sources <span>{view?.sources.length ?? '—'} / 16</span>
            </h3>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Refresh directory status"
              disabled={busy || loading}
              onClick={() => setReload((n) => n + 1)}
            >
              <RefreshCw size={15} />
            </Button>
          </div>
          {loading && !view && (
            <p aria-live="polite">Loading installed sources…</p>
          )}
          {view?.sources.length === 0 && (
            <p className="small muted">
              No directory installed. Start with a manual source scoped to your
              receiving domains.
            </p>
          )}
          <div className="directory-source-list">
            {view?.sources.map((s) => (
              <button
                type="button"
                key={s.source.id}
                disabled={locked}
                className={`directory-source${draft?.source.id === s.source.id ? ' selected' : ''}`}
                aria-pressed={draft?.source.id === s.source.id}
                onClick={() => openSource(s.source.id)}
              >
                <span>
                  <Building2 size={16} />
                  <strong>{s.source.label}</strong>
                </span>
                <small>
                  {s.people} {s.people === 1 ? 'identity' : 'identities'} ·{' '}
                  {s.groups} {s.groups === 1 ? 'group' : 'groups'}
                </small>
                <span className="directory-source-meta">
                  <small>
                    {(
                      {
                        manual: 'Manual',
                        entra: 'Microsoft Entra',
                        okta: 'Okta',
                        google: 'Google Workspace',
                        active_directory: 'Active Directory',
                        aws_identity_store: 'AWS Identity Store',
                        scim: 'SCIM',
                      } as Record<string, string>
                    )[s.source.provider] ?? s.source.provider}
                  </small>
                  <small
                    className={s.fresh ? 'directory-fresh' : 'directory-stale'}
                  >
                    {s.fresh ? 'Current' : 'Stale'}
                  </small>
                </span>
              </button>
            ))}
          </div>
          <Button
            variant="outline"
            disabled={!view || locked || view.sources.length >= 16}
            onClick={() => openSource('')}
          >
            <Plus size={16} /> Add manual source
          </Button>
          <p className="directory-note">
            Collect provider sources above; edit manual sources here. Directory
            collection does not enable SSO sign-in.
          </p>
        </aside>
        <section
          className="directory-content"
          aria-label="Directory source workspace"
          aria-busy={loading || busy}
        >
          {!draft ? (
            <div className="directory-welcome">
              <UsersRound size={40} strokeWidth={1.4} />
              <h3>Your organization, in context</h3>
              <p>
                Select a source to inspect its people and groups, or create a
                manual directory. Explicit aliases and protected roles help
                explain unexpected sender identities.
              </p>
              <div>
                <span>
                  <Check size={16} /> Scoped to receiving domains
                </span>
                <span>
                  <Check size={16} /> Changes reviewed before activation
                </span>
                <span>
                  <Check size={16} /> Same policy across your MX servers
                </span>
              </div>
            </div>
          ) : (
            <>
              <header className="directory-editor-heading">
                <div>
                  <p className="eyebrow">
                    {selectedSource
                      ? 'INSTALLED SOURCE · LOCAL WORKSPACE'
                      : 'NEW MANUAL SOURCE'}
                  </p>
                  <h3>{draft.source.label || 'Untitled source'}</h3>
                  <p>
                    {selectedSource
                      ? `Generation ${selectedSource.generation} · checked ${stamp(selectedSource.completed_at)}`
                      : 'Create identities and assign their explicit addresses.'}
                  </p>
                </div>
                <span className="status">
                  {pending
                    ? 'Prepared · not active'
                    : dirty
                      ? 'Unsaved edits'
                      : 'Installed snapshot'}
                </span>
              </header>
              {!manual && (
                <p className="directory-note">
                  This provider snapshot is read-only. Collect an update above,
                  then review it before activation.
                </p>
              )}
              <SectionTabs
                id={`${id}-editor`}
                label="Directory sections"
                value={tab}
                onChange={(value) => {
                  setTab(value);
                  setQuery('');
                  setPage(0);
                }}
                items={[
                  { id: 'source', label: 'Source' },
                  { id: 'people', label: `People (${draft.people.length})` },
                  { id: 'groups', label: `Groups (${draft.groups.length})` },
                  { id: 'delegations', label: 'Delegation' },
                ]}
              />
              <div
                role="tabpanel"
                id={`${id}-editor-panel-${tab}`}
                aria-labelledby={`${id}-editor-tab-${tab}`}
              >
                {tab === 'source' && (
                  <fieldset
                    className="directory-form"
                    disabled={!manual || locked}
                  >
                    <legend className="sr-only">Source configuration</legend>
                    <div className="form-grid">
                      <label
                        className="field"
                        htmlFor={`${id}-directory-field-1`}
                      >
                        Source name
                        <Input
                          id={`${id}-directory-field-1`}
                          value={draft.source.label}
                          maxLength={200}
                          onChange={(e) =>
                            update({
                              ...draft,
                              source: {
                                ...draft.source,
                                label: e.target.value,
                              },
                            })
                          }
                          placeholder="Organization directory"
                        />
                      </label>
                      <label
                        className="field"
                        htmlFor={`${id}-directory-field-2`}
                      >
                        Stable source ID
                        <Input
                          id={`${id}-directory-field-2`}
                          value={draft.source.id}
                          disabled={!!selectedSource}
                          onChange={(e) =>
                            update({
                              ...draft,
                              source: { ...draft.source, id: e.target.value },
                            })
                          }
                          placeholder="organization-directory"
                        />
                        <small>Keep this ID across updates.</small>
                      </label>
                      <label
                        className="field"
                        htmlFor={`${id}-directory-field-3`}
                      >
                        Directory authority
                        <Input
                          id={`${id}-directory-field-3`}
                          value={draft.source.authority}
                          disabled={!!selectedSource}
                          onChange={(e) =>
                            update({
                              ...draft,
                              source: {
                                ...draft.source,
                                authority: e.target.value,
                              },
                            })
                          }
                        />
                        <small>
                          An organization identifier, independent of email
                          addresses.
                        </small>
                      </label>
                      <label
                        className="field"
                        htmlFor={`${id}-directory-field-4`}
                      >
                        Freshness limit (days)
                        <Input
                          id={`${id}-directory-field-4`}
                          type="number"
                          min={1 / 288}
                          max={30}
                          step="any"
                          value={draft.source.stale_after_seconds / 86400}
                          onChange={(e) =>
                            update({
                              ...draft,
                              source: {
                                ...draft.source,
                                stale_after_seconds: Math.round(
                                  Number(e.target.value) * 86400,
                                ),
                              },
                            })
                          }
                        />
                        <small>
                          Stale data stays visible but cannot corroborate an
                          identity finding.
                        </small>
                      </label>
                    </div>
                    <fieldset className="directory-checks">
                      <legend>Receiving domains</legend>
                      {domains.length === 0 ? (
                        <p>
                          Add a receiving domain in the domain settings first.
                        </p>
                      ) : (
                        domains.map((domain) => (
                          <label key={domain}>
                            <input
                              type="checkbox"
                              checked={draft.source.scopes.includes(domain)}
                              onChange={(e) =>
                                update({
                                  ...draft,
                                  source: {
                                    ...draft.source,
                                    scopes: e.target.checked
                                      ? [...draft.source.scopes, domain]
                                      : draft.source.scopes.filter(
                                          (s) => s !== domain,
                                        ),
                                  },
                                })
                              }
                            />
                            {domain}
                          </label>
                        ))
                      )}
                    </fieldset>
                  </fieldset>
                )}
                {(tab === 'people' || tab === 'groups') && (
                  <>
                    <div className="identity-toolbar">
                      <label
                        className="identity-search"
                        htmlFor={`${id}-directory-field-6`}
                      >
                        <Search size={16} />
                        <Input
                          id={`${id}-directory-field-6`}
                          aria-label={`Search ${tab}`}
                          placeholder="Search name, address or ID"
                          value={query}
                          onChange={(e) => {
                            setQuery(e.target.value);
                            setPage(0);
                          }}
                        />
                      </label>
                      <div className="identity-buttons">
                        {tab === 'people' && manual && (
                          <>
                            <input
                              ref={file}
                              type="file"
                              accept=".csv,text/csv"
                              className="sr-only"
                              tabIndex={-1}
                              onChange={(e) => {
                                void readCsv(e.target.files?.[0]);
                                e.target.value = '';
                              }}
                            />
                            <Button
                              variant="outline"
                              disabled={locked}
                              onClick={() => file.current?.click()}
                            >
                              <Upload size={15} /> Import CSV
                            </Button>
                            <Button variant="ghost" onClick={template}>
                              Template
                            </Button>
                          </>
                        )}
                        <Button
                          disabled={
                            !manual ||
                            locked ||
                            objects.length >= (tab === 'people' ? 20000 : 5000)
                          }
                          onClick={() =>
                            setEditing(
                              tab === 'people'
                                ? {
                                    kind: 'person',
                                    original: null,
                                    value: emptyPerson(),
                                  }
                                : {
                                    kind: 'group',
                                    original: null,
                                    value: emptyGroup(),
                                  },
                            )
                          }
                        >
                          <Plus size={16} /> Add{' '}
                          {tab === 'people' ? 'identity' : 'group'}
                        </Button>
                      </div>
                    </div>
                    {matches.length === 0 ? (
                      <div className="identity-empty">
                        <Users size={28} />
                        <h4>
                          {query
                            ? 'No matching identities'
                            : tab === 'people'
                              ? 'No identities yet'
                              : 'No groups yet'}
                        </h4>
                        <p>
                          {query
                            ? 'Try a name, explicit address or stable ID.'
                            : 'Add an entry to this local workspace, then review the source changes.'}
                        </p>
                      </div>
                    ) : (
                      <ul className="directory-objects">
                        {matches
                          .slice(actualPage * 25, (actualPage + 1) * 25)
                          .map((p) => (
                            <li key={p.id}>
                              <span
                                className="directory-avatar"
                                aria-hidden="true"
                              >
                                {p.display_name.slice(0, 1).toUpperCase()}
                              </span>
                              <div className="directory-object-text">
                                <strong>{p.display_name}</strong>
                                <span>
                                  {p.addresses.join(' · ') ||
                                    'No sending address assigned'}
                                </span>
                                <small>
                                  {p.id} · {p.activity}
                                  {'kind' in p
                                    ? ` · ${p.kind.replaceAll('_', ' ')}`
                                    : ''}
                                </small>
                                <div className="directory-tags">
                                  {'protected_roles' in p
                                    ? p.protected_roles.map((role) => (
                                        <span key={role}>
                                          <ShieldCheck size={12} />
                                          {role}
                                        </span>
                                      ))
                                    : p.protected && (
                                        <span>
                                          <ShieldCheck size={12} />
                                          Protected group
                                        </span>
                                      )}
                                </div>
                              </div>
                              <div className="identity-buttons">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  aria-label={`Edit ${p.display_name}`}
                                  disabled={!manual || locked}
                                  onClick={() =>
                                    setEditing(
                                      tab === 'people'
                                        ? {
                                            kind: 'person',
                                            original: p.id,
                                            value: structuredClone(p as Person),
                                          }
                                        : {
                                            kind: 'group',
                                            original: p.id,
                                            value: structuredClone(p as Group),
                                          },
                                    )
                                  }
                                >
                                  <Pencil size={15} />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  aria-label={`Remove ${p.display_name}`}
                                  disabled={!manual || locked}
                                  onClick={() =>
                                    setDeletion({
                                      kind:
                                        tab === 'people' ? 'person' : 'group',
                                      id: p.id,
                                      label: p.display_name,
                                    })
                                  }
                                >
                                  <Trash2 size={15} />
                                </Button>
                              </div>
                            </li>
                          ))}
                      </ul>
                    )}
                    {matches.length > 25 && (
                      <div className="directory-pagination">
                        <Button
                          variant="outline"
                          disabled={actualPage === 0}
                          onClick={() => setPage(actualPage - 1)}
                        >
                          Previous
                        </Button>
                        <span>
                          Page {actualPage + 1} of{' '}
                          {Math.ceil(matches.length / 25)} · {matches.length}{' '}
                          results
                        </span>
                        <Button
                          variant="outline"
                          disabled={(actualPage + 1) * 25 >= matches.length}
                          onClick={() => setPage(actualPage + 1)}
                        >
                          Next
                        </Button>
                      </div>
                    )}
                    {tab === 'groups' && (
                      <fieldset
                        disabled={!manual || locked}
                        className="directory-relations"
                      >
                        <legend>Group membership</legend>
                        <p className="small muted">
                          Membership helps resolve protected groups. It does not
                          grant mailbox access or create mailing lists.
                        </p>
                        <label className="field">
                          Group
                          <select
                            value={groupId}
                            onChange={(e) => setGroupId(e.target.value)}
                          >
                            <option value="">Choose a group</option>
                            {draft.groups.map((g) => (
                              <option key={g.id} value={g.id}>
                                {g.display_name} ({g.id})
                              </option>
                            ))}
                          </select>
                        </label>
                        {currentMembers.length > 0 && (
                          <ul className="directory-links">
                            {currentMembers.map((m) => (
                              <li key={`${m.member.kind}:${m.member.id}`}>
                                <span>
                                  {(m.member.kind === 'person'
                                    ? draft.people
                                    : draft.groups
                                  ).find((p) => p.id === m.member.id)
                                    ?.display_name ?? m.member.id}{' '}
                                  <small>
                                    {m.member.kind} · {m.member.id}
                                  </small>
                                </span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  aria-label={`Remove member ${m.member.id}`}
                                  onClick={() =>
                                    update({
                                      ...draft,
                                      memberships: draft.memberships.filter(
                                        (x) => x !== m,
                                      ),
                                    })
                                  }
                                >
                                  <Trash2 size={14} />
                                </Button>
                              </li>
                            ))}
                          </ul>
                        )}
                        <div className="directory-inline">
                          <label className="field">
                            Member type
                            <select
                              value={memberKind}
                              onChange={(e) => {
                                setMemberKind(
                                  e.target.value as 'person' | 'group',
                                );
                                setMemberId('');
                              }}
                            >
                              <option value="person">Person / mailbox</option>
                              <option value="group">Nested group</option>
                            </select>
                          </label>
                          <label className="field">
                            Member
                            <select
                              value={memberId}
                              onChange={(e) => setMemberId(e.target.value)}
                            >
                              <option value="">Choose an identity</option>
                              {(memberKind === 'person'
                                ? draft.people
                                : draft.groups.filter((g) => g.id !== groupId)
                              ).map((p) => (
                                <option key={p.id} value={p.id}>
                                  {p.display_name} ({p.id})
                                </option>
                              ))}
                            </select>
                          </label>
                          <Button
                            variant="outline"
                            disabled={
                              !groupId ||
                              !memberId ||
                              draft.memberships.some(
                                (m) =>
                                  m.group === groupId &&
                                  m.member.kind === memberKind &&
                                  m.member.id === memberId,
                              )
                            }
                            onClick={() => {
                              update({
                                ...draft,
                                memberships: [
                                  ...draft.memberships,
                                  {
                                    group: groupId,
                                    member: { kind: memberKind, id: memberId },
                                  },
                                ],
                              });
                              setMemberId('');
                            }}
                          >
                            Add member
                          </Button>
                        </div>
                      </fieldset>
                    )}
                  </>
                )}
                {tab === 'delegations' && (
                  <fieldset
                    disabled={!manual || locked}
                    className="directory-relations"
                  >
                    <legend>Explicit sending delegation</legend>
                    <p className="small muted">
                      Record who is authorized to send using another identity’s
                      address. This records an assignment; it does not grant
                      permissions at your mail provider.
                    </p>
                    {draft.delegations.length === 0 && (
                      <p className="identity-empty">
                        No sending delegation recorded.
                      </p>
                    )}
                    <ul className="directory-links">
                      {draft.delegations.map((d, i) => (
                        <li key={`${d.owner}:${d.delegate}:${d.address}`}>
                          <span>
                            <strong>
                              {draft.people.find((p) => p.id === d.delegate)
                                ?.display_name ?? d.delegate}
                            </strong>{' '}
                            → {d.address}
                            <small>
                              Owner:{' '}
                              {draft.people.find((p) => p.id === d.owner)
                                ?.display_name ?? d.owner}
                            </small>
                          </span>
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-label={`Remove delegation for ${d.address}`}
                            onClick={() =>
                              update({
                                ...draft,
                                delegations: draft.delegations.filter(
                                  (_, n) => n !== i,
                                ),
                              })
                            }
                          >
                            <Trash2 size={14} />
                          </Button>
                        </li>
                      ))}
                    </ul>
                    <div className="form-grid">
                      <label className="field">
                        Address owner
                        <select
                          value={owner}
                          onChange={(e) => {
                            setOwner(e.target.value);
                            setDelegatedAddress('');
                          }}
                        >
                          <option value="">Choose an identity</option>
                          {draft.people.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.display_name} ({p.id})
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="field">
                        Delegated address
                        <select
                          value={delegatedAddress}
                          onChange={(e) => setDelegatedAddress(e.target.value)}
                        >
                          <option value="">Choose an explicit address</option>
                          {ownerPerson?.addresses.map((a) => (
                            <option key={a}>{a}</option>
                          ))}
                        </select>
                      </label>
                      <label className="field">
                        Authorized delegate
                        <select
                          value={delegate}
                          onChange={(e) => setDelegate(e.target.value)}
                        >
                          <option value="">Choose another identity</option>
                          {draft.people
                            .filter((p) => p.id !== owner)
                            .map((p) => (
                              <option key={p.id} value={p.id}>
                                {p.display_name} ({p.id})
                              </option>
                            ))}
                        </select>
                      </label>
                    </div>
                    <Button
                      variant="outline"
                      disabled={
                        !owner ||
                        !delegate ||
                        owner === delegate ||
                        !delegatedAddress ||
                        draft.delegations.some(
                          (d) =>
                            d.owner === owner &&
                            d.delegate === delegate &&
                            d.address === delegatedAddress,
                        )
                      }
                      onClick={() => {
                        update({
                          ...draft,
                          delegations: [
                            ...draft.delegations,
                            { owner, delegate, address: delegatedAddress },
                          ],
                        });
                        setDelegate('');
                      }}
                    >
                      Add delegation
                    </Button>
                  </fieldset>
                )}
              </div>
              <footer className="directory-footer">
                <div>
                  <strong>
                    {dirty ? 'Local changes · not active' : 'Installed source'}
                  </strong>
                  <p>
                    {sourceProblem ||
                      'Preparing validates the complete source and shows its changes before activation.'}
                  </p>
                </div>
                <div className="identity-buttons">
                  {dirty && (
                    <Button
                      variant="ghost"
                      disabled={locked}
                      onClick={() => setDiscardLocal(true)}
                    >
                      Discard local edits
                    </Button>
                  )}
                  {selectedSource && (
                    <Button
                      variant="ghost"
                      disabled={locked}
                      onClick={() =>
                        setDeletion({
                          kind: 'source',
                          id: selectedSource.source.id,
                          label: selectedSource.source.label,
                        })
                      }
                    >
                      Remove source
                    </Button>
                  )}
                  <Button
                    disabled={!manual || locked || !!sourceProblem}
                    onClick={() =>
                      void prepare({ operation: 'upsert_manual', draft })
                    }
                  >
                    {busy
                      ? 'Preparing…'
                      : dirty
                        ? 'Prepare changes'
                        : 'Renew reviewed source'}
                    <ArrowRight size={16} />
                  </Button>
                </div>
              </footer>
            </>
          )}
        </section>
      </div>
      {discardLocal && (
        <ConfirmDialog
          title="Discard local source edits?"
          confirmLabel="Discard local edits"
          busy={false}
          onCancel={() => setDiscardLocal(false)}
          onConfirm={() => {
            setDraft(original ? JSON.parse(original) : null);
            setPrepared(null);
            setEditing(null);
            setImported(null);
            setDiscardLocal(false);
            setError('');
          }}
        >
          <p>
            Restore the loaded source in this workspace. Installed configuration
            and other policy edits are retained.
          </p>
        </ConfirmDialog>
      )}
      {switchTo !== null && (
        <ConfirmDialog
          title="Discard local source edits?"
          confirmLabel="Discard and continue"
          busy={false}
          onCancel={() => setSwitchTo(null)}
          onConfirm={() => {
            const next = switchTo;
            setSwitchTo(null);
            void loadSource(next);
          }}
        >
          <p>
            Your unsaved source edits will be discarded. Installed settings
            remain available.
          </p>
        </ConfirmDialog>
      )}
      {editing && draft && (
        <ConfirmDialog
          title={
            editing.original
              ? 'Edit directory identity'
              : editing.kind === 'person'
                ? 'Add directory identity'
                : 'Add directory group'
          }
          confirmLabel="Save to source workspace"
          confirmDisabled={!!editError || locked}
          busy={false}
          onCancel={() => setEditing(null)}
          onConfirm={() => {
            if (editError || locked) return;
            const value = editing.value;
            if (editing.kind === 'person')
              update({
                ...draft,
                people: editing.original
                  ? draft.people.map((p) =>
                      p.id === editing.original ? (value as Person) : p,
                    )
                  : [...draft.people, value as Person],
              });
            else
              update({
                ...draft,
                groups: editing.original
                  ? draft.groups.map((p) =>
                      p.id === editing.original ? (value as Group) : p,
                    )
                  : [...draft.groups, value as Group],
              });
            setEditing(null);
          }}
        >
          <div className="directory-form">
            <label className="field" htmlFor={`${id}-directory-field-13`}>
              Stable identity ID
              <Input
                id={`${id}-directory-field-13`}
                autoComplete="off"
                disabled={editing.original !== null}
                value={editing.value.id}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    value: { ...editing.value, id: e.target.value },
                  } as ObjectEdit)
                }
              />
            </label>
            <label className="field" htmlFor={`${id}-directory-field-14`}>
              Display name
              <Input
                id={`${id}-directory-field-14`}
                value={editing.value.display_name}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    value: { ...editing.value, display_name: e.target.value },
                  } as ObjectEdit)
                }
              />
            </label>
            <div className="form-grid">
              {editing.kind === 'person' && (
                <label className="field">
                  Identity type
                  <select
                    value={editing.value.kind}
                    onChange={(e) =>
                      setEditing({
                        ...editing,
                        value: {
                          ...editing.value,
                          kind: e.target.value as Person['kind'],
                        },
                      })
                    }
                  >
                    <option value="person">Person</option>
                    <option value="shared_mailbox">Shared mailbox</option>
                    <option value="supplier">Supplier</option>
                  </select>
                </label>
              )}
              <label className="field">
                Activity
                <select
                  value={editing.value.activity}
                  onChange={(e) =>
                    setEditing({
                      ...editing,
                      value: {
                        ...editing.value,
                        activity: e.target.value as Activity,
                      },
                    } as ObjectEdit)
                  }
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="unknown">Unknown</option>
                </select>
              </label>
            </div>
            <label className="field">
              Explicit addresses and aliases
              <textarea
                rows={3}
                defaultValue={editing.value.addresses.join('\n')}
                spellCheck={false}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    value: {
                      ...editing.value,
                      addresses: addressList(e.target.value),
                    },
                  } as ObjectEdit)
                }
              />
              <small>
                One address per line. Aliases are not inferred from login names.
              </small>
            </label>
            {editing.kind === 'person' ? (
              <fieldset className="directory-checks">
                <legend>Protected roles</legend>
                {roles.map((role) => (
                  <label key={role}>
                    <input
                      type="checkbox"
                      checked={editing.value.protected_roles.includes(role)}
                      onChange={(e) =>
                        setEditing({
                          ...editing,
                          value: {
                            ...editing.value,
                            protected_roles: e.target.checked
                              ? [...editing.value.protected_roles, role]
                              : editing.value.protected_roles.filter(
                                  (r) => r !== role,
                                ),
                          },
                        })
                      }
                    />
                    {role}
                  </label>
                ))}
              </fieldset>
            ) : (
              <label className="directory-check">
                <input
                  type="checkbox"
                  checked={editing.value.protected}
                  onChange={(e) =>
                    setEditing({
                      ...editing,
                      value: { ...editing.value, protected: e.target.checked },
                    })
                  }
                />
                Protect this group’s identity
              </label>
            )}
            {editError && (
              <p className="small directory-validation" aria-live="polite">
                {editError}
              </p>
            )}
            <p className="small muted">
              This saves a local edit. Review the complete source before
              applying it.
            </p>
          </div>
        </ConfirmDialog>
      )}
      {deletion && draft && (
        <ConfirmDialog
          title={`Remove ${deletion.kind === 'source' ? 'directory source' : 'identity'}?`}
          confirmLabel={
            deletion.kind === 'source'
              ? 'Prepare removal'
              : 'Remove from workspace'
          }
          danger
          busy={busy}
          confirmDisabled={locked}
          onCancel={() => setDeletion(null)}
          onConfirm={() => {
            const d = deletion;
            setDeletion(null);
            if (d.kind === 'source')
              void prepare({ operation: 'remove', source_id: d.id });
            else
              update(
                d.kind === 'person'
                  ? removePerson(draft, d.id)
                  : removeGroup(draft, d.id),
              );
          }}
        >
          <p>
            <strong>{deletion.label}</strong> will be removed{' '}
            {deletion.kind === 'source'
              ? 'in the proposed directory'
              : 'from this local workspace'}
            .
          </p>
          <p>
            Related memberships and delegations are removed with an identity.
            Activation still requires review of the complete change.
          </p>
        </ConfirmDialog>
      )}
      {imported && draft && (
        <ConfirmDialog
          title="Review people import"
          confirmLabel="Merge into source workspace"
          busy={false}
          confirmDisabled={!importPreview || locked}
          onCancel={() => setImported(null)}
          onConfirm={() => {
            if (importPreview) {
              update({ ...draft, people: importPreview.people });
              setImported(null);
            }
          }}
        >
          <p>
            {importPreview
              ? `${importPreview.added} new identities · ${importPreview.changed} changed identities · ${importPreview.people.length} total`
              : importError}
          </p>
          <p>
            Rows match by stable ID. Imported rows replace the fields of
            matching identities; other people, groups and memberships are
            retained. Invalid references are checked when preparing the source.
          </p>
          <p>This changes only your local workspace.</p>
        </ConfirmDialog>
      )}
      {prepared && (
        <ConfirmDialog
          title="Review prepared directory"
          confirmLabel="Add to policy draft"
          busy={false}
          confirmDisabled={
            locked || !preparedMatches(prepared, revision, installedHash)
          }
          onCancel={() => setPrepared(null)}
          onConfirm={() => {
            if (!preparedMatches(prepared, revision, installedHash)) return;
            onChange(prepared.selection);
            setPrepared(null);
            setNotice(
              'Snapshot prepared. Use the page’s Review and apply control to activate the policy.',
            );
          }}
        >
          <DirectoryReview prepared={prepared} />
        </ConfirmDialog>
      )}
    </section>
  );
}

export function DirectoryReview({ prepared }: { prepared: DirectoryPrepared }) {
  const r = prepared.review;
  return (
    <div className="directory-review">
      <p>
        <strong>{r.source_label}</strong> · {r.operation} source
      </p>
      <div className="directory-review-grid">
        {[
          ['People', r.people],
          ['Groups', r.groups],
        ].map(([label, value]) => {
          const c = value as typeof r.people;
          return (
            <div key={label as string}>
              <strong>{label as string}</strong>
              <span>{c.added} added</span>
              <span>{c.changed} changed</span>
              <span>{c.removed} removed</span>
            </div>
          );
        })}
      </div>
      <dl>
        <div>
          <dt>Membership changes</dt>
          <dd>{r.membership_changes}</dd>
        </div>
        <div>
          <dt>Delegation changes</dt>
          <dd>{r.delegation_changes}</dd>
        </div>
        <div>
          <dt>Active identities removed or disabled</dt>
          <dd>{r.removed_or_disabled}</dd>
        </div>
        <div>
          <dt>Protected identity changes</dt>
          <dd>{r.protected_identity_changes}</dd>
        </div>
      </dl>
      {r.requires_attention && (
        <p className="directory-attention">
          <ShieldCheck size={17} />
          This change affects source configuration or existing identity
          protection. Check the intended removals and assignments before
          continuing.
        </p>
      )}
      {r.after && (
        <p className="small muted">
          <Clock3 size={14} /> Generation {r.after.generation} ·{' '}
          {r.after.source.scopes.join(', ')} · {stamp(r.after.completed_at)}
        </p>
      )}
      <p>
        No change is active yet. Add this snapshot to the policy draft, then use
        the normal configuration review and MX activation.
      </p>
      <details>
        <summary>Snapshot provenance</summary>
        <code>{prepared.selection.sha256}</code>
        <p>Based on revision {prepared.revision}</p>
      </details>
    </div>
  );
}
