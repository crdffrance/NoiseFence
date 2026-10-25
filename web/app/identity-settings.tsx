import { useEffect, useId, useRef, useState } from 'react';
import {
  Fingerprint,
  Plus,
  Search,
  Trash2,
  Upload,
  ArrowUpRight,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { ConfirmDialog } from './console-ui';
import type { ProtectionPolicy, ProviderState } from './protection';
import {
  MAX_IDENTITY_CSV_BYTES,
  MAX_PROTECTED_NAMES,
  matchesProtectedName,
  parseIdentityCsv,
  previewIdentityImport,
  protectedNameConflicts,
  protectedNameError,
  type ProtectedName,
} from './identity-editor';

export function IdentitySettings({
  policy,
  installed,
  revision,
  domains,
  onChange,
  onProtection,
}: {
  policy: ProtectionPolicy | null;
  installed: ProtectionPolicy | null;
  revision: number;
  domains: string[];
  onChange: (value: ProtectionPolicy) => void;
  onProtection: () => void;
}) {
  const id = useId(),
    input = useRef<HTMLInputElement>(null),
    request = useRef(0);
  const [availability, setAvailability] = useState<{
      key: string;
      available: boolean | null;
      error: string;
    } | null>(null),
    [attempt, setAttempt] = useState(0),
    [query, setQuery] = useState(''),
    [selection, setSelection] = useState<{ key: string; indices: number[] }>({
      key: '',
      indices: [],
    }),
    [removal, setRemoval] = useState<{ key: string; indices: number[] } | null>(
      null,
    ),
    [imported, setImported] = useState<ProtectedName[] | null>(null),
    [importError, setImportError] = useState(''),
    [reading, setReading] = useState(false),
    [notice, setNotice] = useState('');
  const rows = policy?.protected_names ?? [];
  const revisionKey = JSON.stringify([revision, policy?.identity, rows]);
  const statusKey = `${revision}:${attempt}`;
  const available =
    availability?.key === statusKey ? availability.available : null;
  const loadError = availability?.key === statusKey ? availability.error : '';
  const selected = selection.key === revisionKey ? selection.indices : [];
  const remove = removal?.key === revisionKey ? removal.indices : null;
  const setSelected = (value: number[] | ((previous: number[]) => number[])) =>
    setSelection((previous) => ({
      key: revisionKey,
      indices:
        typeof value === 'function'
          ? value(previous.key === revisionKey ? previous.indices : [])
          : value,
    }));
  const setRemove = (indices: number[] | null) =>
    setRemoval(indices ? { key: revisionKey, indices } : null);
  useEffect(() => {
    const controller = new AbortController();
    api<ProviderState>('/admin/protection', undefined, undefined, {
      signal: controller.signal,
    })
      .then((status) => {
        if (!controller.signal.aborted)
          setAvailability({
            key: statusKey,
            available: status.available,
            error: '',
          });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setAvailability({
            key: statusKey,
            available: null,
            error: error.message,
          });
      });
    return () => controller.abort();
  }, [statusKey]);
  // Selection and removal are bound to the exact draft; a parent reload or edit
  // cannot make an old row index remove a different identity.
  useEffect(
    () => () => {
      request.current++;
    },
    [],
  );
  const update = (values: ProtectedName[]) => {
    if (policy) onChange({ ...policy, protected_names: values });
  };
  const canEdit = available === true && policy !== null;
  const visible = rows
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => matchesProtectedName(entry, query));
  const conflicts = protectedNameConflicts(rows);
  const invalid = rows.filter((entry) => protectedNameError(entry)).length;
  const changed =
    JSON.stringify([policy?.identity, rows]) !==
    JSON.stringify([installed?.identity, installed?.protected_names ?? []]);
  let preview: ReturnType<typeof previewIdentityImport> | null = null,
    previewError = '';
  if (imported) {
    try {
      preview = previewIdentityImport(imported, rows);
    } catch (e) {
      previewError = (e as Error).message;
    }
  }
  async function readCsv(file?: File) {
    if (!file) return;
    const sequence = ++request.current;
    setImportError('');
    setNotice('');
    setReading(true);
    try {
      if (file.size > MAX_IDENTITY_CSV_BYTES)
        throw new Error('The CSV must be at most 64 KiB.');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(
        await file.arrayBuffer(),
      );
      const entries = parseIdentityCsv(text);
      if (sequence === request.current) setImported(entries);
    } catch (e) {
      if (sequence === request.current) setImportError((e as Error).message);
    } finally {
      if (sequence === request.current) setReading(false);
    }
  }
  function template() {
    const url = URL.createObjectURL(
      new Blob(
        [
          'name,domain\r\nAlex Morgan,example.test\r\nFinance Team,example.test\r\n',
        ],
        { type: 'text/csv;charset=utf-8' },
      ),
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = 'noisefence-protected-names.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <section className="identity-workspace" aria-labelledby={`${id}-title`}>
      <header className="identity-intro">
        <div className="identity-emblem">
          <Fingerprint size={28} aria-hidden="true" />
        </div>
        <div>
          <p className="eyebrow">SENDER CONTEXT</p>
          <h2 id={`${id}-title`}>Identity protection</h2>
          <p>
            Recognize familiar names used from an unexpected sending domain.
          </p>
        </div>
        <span className="identity-badge">Observation only</span>
      </header>
      <div className="identity-overview">
        <div>
          <small>Protected names · draft</small>
          <strong>
            {rows.length}
            <span> / {MAX_PROTECTED_NAMES}</span>
          </strong>
        </div>
        <div>
          <small>Receiving domains · draft</small>
          <strong>{domains.length}</strong>
        </div>
        <div>
          <small>Loaded configuration</small>
          <strong>{installed?.identity ? 'Enabled' : 'Disabled'}</strong>
          <span>Revision {revision} · check activation below</span>
        </div>
      </div>
      <section className="panel identity-controls">
        <div className="identity-section-heading">
          <div>
            <h3>What this check does</h3>
            <p>
              Names and domain similarities provide context. A familiar name or
              passing DMARC does not prove who wrote a message.
            </p>
          </div>
          <ShieldCheck size={22} aria-hidden="true" />
        </div>
        <ul className="identity-coverage">
          <li>
            <strong>Display names</strong>
            <span>
              Compare a configured name with its expected sending domain.
            </span>
          </li>
          <li>
            <strong>Similar domains</strong>
            <span>
              Look for sender domains resembling your receiving domains.
            </span>
          </li>
          <li>
            <strong>Reply destinations</strong>
            <span>Record a Reply-To domain different from the sender.</span>
          </li>
        </ul>
        <label
          className="toggle-row"
          htmlFor={`${id}-enabled`}
          aria-label="Observe identity signals"
        >
          <span>
            <strong>Observe identity signals</strong>
            <small>
              Draft setting. Findings add context; this module does not directly
              change the score or delivery.
            </small>
          </span>
          <input
            id={`${id}-enabled`}
            type="checkbox"
            role="switch"
            checked={policy?.identity ?? false}
            aria-checked={policy?.identity ?? false}
            disabled={!canEdit}
            onChange={(e) => {
              if (policy) onChange({ ...policy, identity: e.target.checked });
            }}
          />
        </label>
        {loadError ? (
          <p className="error" role="alert">
            Availability could not be loaded: {loadError}{' '}
            <Button variant="outline" onClick={() => setAttempt((x) => x + 1)}>
              Retry availability
            </Button>
          </p>
        ) : available === null ? (
          <output className="muted">Checking module availability…</output>
        ) : !available ? (
          <p className="notice">
            The protection module must be installed on the server before these
            settings can be applied.
          </p>
        ) : !policy ? (
          <p className="notice">
            Additional protection is disabled.{' '}
            <Button variant="outline" onClick={onProtection}>
              Open protection settings <ArrowUpRight size={14} />
            </Button>
          </p>
        ) : null}
      </section>
      <section
        className="panel identity-directory"
        aria-labelledby={`${id}-names`}
      >
        <div className="identity-section-heading">
          <div>
            <h3 id={`${id}-names`}>Protected names</h3>
            <p>
              Manage people, team names and brands. These mappings apply to all
              receiving domains on this installation.
            </p>
          </div>
          <span className={`status ${changed ? 'review' : ''}`}>
            {changed ? 'Unsaved draft' : 'Loaded settings'}
          </span>
        </div>
        <div className="identity-toolbar">
          <label className="identity-search" htmlFor={`${id}-search`}>
            <Search size={16} aria-hidden="true" />
            <span className="sr-only">Search protected names</span>
            <Input
              id={`${id}-search`}
              type="search"
              value={query}
              placeholder="Search name or domain"
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <div className="identity-buttons">
            <Button
              variant="outline"
              disabled={!canEdit || reading}
              onClick={() => input.current?.click()}
            >
              <Upload size={15} />
              {reading ? 'Reading CSV…' : 'Import CSV'}
            </Button>
            <Button
              disabled={!canEdit || rows.length >= MAX_PROTECTED_NAMES}
              onClick={() => {
                setQuery('');
                update([...rows, { name: '', domain: '' }]);
                requestAnimationFrame(() =>
                  document.getElementById(`${id}-name-${rows.length}`)?.focus(),
                );
              }}
            >
              <Plus size={16} />
              Add name
            </Button>
          </div>
          <input
            ref={input}
            type="file"
            accept=".csv,text/csv"
            className="sr-only"
            tabIndex={-1}
            aria-label="Import protected names CSV"
            disabled={!canEdit || reading}
            onChange={(e) => {
              void readCsv(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
        </div>
        {importError && (
          <p role="alert" className="error">
            {importError}
          </p>
        )}
        {notice && <output className="notice">{notice}</output>}
        {!policy?.identity && rows.length > 0 && (
          <p className="notice">
            Identity observations are disabled in this draft. Names are retained
            for later use.
          </p>
        )}
        {!!invalid && (
          <p className="error" role="alert">
            {invalid} {invalid === 1 ? 'row needs' : 'rows need'} correction
            before applying settings.
          </p>
        )}
        {conflicts.length > 0 && (
          <p className="notice">
            Some names map to multiple domains. Each mapping is evaluated
            independently; this is not an allowed-domain list. Review the
            highlighted rows to avoid misleading findings.
          </p>
        )}
        <div className="identity-selection">
          <label>
            <input
              type="checkbox"
              aria-label="Select all visible protected names"
              ref={(node) => {
                if (node)
                  node.indeterminate =
                    visible.some(({ index }) => selected.includes(index)) &&
                    !visible.every(({ index }) => selected.includes(index));
              }}
              disabled={!canEdit || !visible.length}
              checked={
                visible.length > 0 &&
                visible.every(({ index }) => selected.includes(index))
              }
              onChange={(e) =>
                setSelected(
                  e.target.checked ? visible.map(({ index }) => index) : [],
                )
              }
            />
            Select visible
          </label>
          <output>
            {visible.length} of {rows.length} names
            {selected.length ? ` · ${selected.length} selected` : ''}
          </output>
          {selected.length > 0 && (
            <Button
              variant="ghost"
              disabled={!canEdit}
              onClick={() => setRemove(selected)}
            >
              <Trash2 size={14} />
              Remove selected
            </Button>
          )}
        </div>
        {visible.length ? (
          <ul className="identity-rows">
            {visible.map(({ entry, index }) => {
              const error = protectedNameError(entry),
                conflict = conflicts.includes(entry.name.trim().toLowerCase());
              return (
                <li
                  key={index}
                  className={
                    error || conflict
                      ? 'identity-row has-issue'
                      : 'identity-row'
                  }
                >
                  <input
                    type="checkbox"
                    aria-label={`Select ${entry.name || `name ${index + 1}`}`}
                    disabled={!canEdit}
                    checked={selected.includes(index)}
                    onChange={(e) =>
                      setSelected((previous) =>
                        e.target.checked
                          ? [...previous, index]
                          : previous.filter((i) => i !== index),
                      )
                    }
                  />
                  <label className="field" htmlFor={`${id}-name-${index}`}>
                    Display name
                    <Input
                      id={`${id}-name-${index}`}
                      autoComplete="off"
                      spellCheck={false}
                      disabled={!canEdit}
                      value={entry.name}
                      aria-invalid={!!error}
                      aria-describedby={
                        error ? `${id}-error-${index}` : undefined
                      }
                      onChange={(e) =>
                        update(
                          rows.map((row, i) =>
                            i === index
                              ? { ...row, name: e.target.value }
                              : row,
                          ),
                        )
                      }
                    />
                  </label>
                  <label className="field" htmlFor={`${id}-domain-${index}`}>
                    Expected sending domain
                    <Input
                      id={`${id}-domain-${index}`}
                      autoComplete="off"
                      spellCheck={false}
                      disabled={!canEdit}
                      value={entry.domain}
                      aria-invalid={!!error}
                      aria-describedby={
                        error ? `${id}-error-${index}` : undefined
                      }
                      onChange={(e) =>
                        update(
                          rows.map((row, i) =>
                            i === index
                              ? { ...row, domain: e.target.value }
                              : row,
                          ),
                        )
                      }
                    />
                  </label>
                  <Button
                    variant="ghost"
                    disabled={!canEdit}
                    aria-label={`Remove ${entry.name || `name ${index + 1}`}`}
                    onClick={() => setRemove([index])}
                  >
                    <Trash2 size={16} />
                  </Button>
                  {(error || conflict) && (
                    <p
                      id={`${id}-error-${index}`}
                      className="identity-row-help"
                    >
                      {error ??
                        'This display name has another domain mapping. Verify the intended domain.'}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="identity-empty">
            <Users size={28} aria-hidden="true" />
            <h4>
              {rows.length
                ? 'No matching names'
                : 'Start with the names people trust'}
            </h4>
            <p>
              {rows.length
                ? 'Try another name or domain. Your other mappings are still in the draft.'
                : 'Add a person, a finance team or a supplier name and its usual sending domain.'}
            </p>
            {rows.length > 0 && (
              <Button variant="outline" onClick={() => setQuery('')}>
                Clear search
              </Button>
            )}
          </div>
        )}
        <div className="identity-footer">
          <p>
            Exact display-name match after trimming and case normalization.
            Sending domains are compared by registrable domain, so subdomains
            are not separate identities.
          </p>
          <Button variant="ghost" onClick={template}>
            Download CSV template
          </Button>
        </div>
        <p className="small muted">
          CSV: UTF-8, name and domain columns, up to 100 rows and 64 KiB. Import
          adds to the draft after preview; it never replaces the list. Use{' '}
          <strong>Review and apply</strong> below, then wait for MX activation.
        </p>
      </section>
      <details className="panel identity-boundaries">
        <summary>Coverage and directory integrations</summary>
        <p>
          These settings manage display-name observations. Use the directory
          section to collect and review identities from Entra ID, Google
          Workspace, Okta or AWS Identity Store. A connector becomes available
          only after you configure authorized access. Active Directory and SCIM
          collection are still under development.
        </p>
        <p>
          Domain authentication, relationship history and identity are separate
          evidence. A new contact is not automatically spam; a familiar contact
          can still be compromised. Shared mailboxes, aliases and delegations
          require explicit directory support.
        </p>
        <Button variant="outline" onClick={onProtection}>
          Reply-To exceptions and reputation <ArrowUpRight size={14} />
        </Button>
      </details>
      {remove && (
        <ConfirmDialog
          title={`Remove ${remove.length === 1 ? 'this name' : `${remove.length} names`} from the draft?`}
          confirmLabel="Remove from draft"
          danger
          busy={false}
          confirmDisabled={!canEdit}
          onCancel={() => setRemove(null)}
          onConfirm={() => {
            if (!canEdit) return;
            update(rows.filter((_, i) => !remove.includes(i)));
            setRemove(null);
            requestAnimationFrame(() =>
              document.getElementById(`${id}-search`)?.focus(),
            );
            setNotice(
              'Names removed from the draft. Review and apply to save this change.',
            );
          }}
        >
          <p>
            Loaded settings remain unchanged until you review and apply.
            Removing a mapping does not remove messages, accounts or receiving
            domains.
          </p>
          <ul>
            {remove.map((index) => (
              <li key={index}>
                {rows[index]?.name || 'Unnamed entry'} ·{' '}
                {rows[index]?.domain || 'No domain'}
              </li>
            ))}
          </ul>
        </ConfirmDialog>
      )}
      {imported && (
        <ConfirmDialog
          title="Review CSV import"
          confirmLabel="Add to draft"
          busy={false}
          confirmDisabled={
            !canEdit || !!previewError || !preview?.additions.length
          }
          onCancel={() => setImported(null)}
          onConfirm={() => {
            if (!canEdit || !preview?.additions.length) return;
            update([...rows, ...preview.additions]);
            setNotice(
              `${preview.additions.length} ${preview.additions.length === 1 ? 'name' : 'names'} added to the draft. Review and apply to save.`,
            );
            setImported(null);
            setQuery('');
          }}
        >
          <p>No settings have been saved. Existing mappings will be kept.</p>
          {previewError ? (
            <p className="error" role="alert">
              {previewError}
            </p>
          ) : (
            preview && (
              <>
                <p>
                  <strong>
                    {preview.additions.length} new{' '}
                    {preview.additions.length === 1 ? 'name' : 'names'}
                  </strong>{' '}
                  · {preview.duplicates} duplicate{' '}
                  {preview.duplicates === 1 ? 'row' : 'rows'} skipped.
                </p>
                <div className="identity-import-list">
                  {preview.additions.map((entry, i) => (
                    <p key={i}>
                      <strong>{entry.name}</strong>
                      <span>{entry.domain}</span>
                    </p>
                  ))}
                </div>
              </>
            )
          )}
        </ConfirmDialog>
      )}
    </section>
  );
}
