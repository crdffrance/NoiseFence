import { useEffect, useId, useState } from 'react';
import { api, type User } from './client';
import { ConfirmDialog } from './console-ui';
import { sourceError, type Source, type DirectoryDraft } from './directory';
import {
  connectionLifetimeError,
  type SavedConnection,
} from './directory-connections';

export function scimFormError(source: Source, domains: string[], days: number) {
  if (source.provider !== 'scim') return 'Choose a SCIM source.';
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(source.id))
    return 'Use a stable source ID of 1–100 letters, digits, underscores or hyphens, starting with a letter or digit.';
  return (
    sourceError({ ...source, provider: 'manual' }, domains) ||
    (!Number.isInteger(days) || days < 1 || days > 90
      ? 'Choose a lifetime from 1 to 90 whole days.'
      : connectionLifetimeError('scim', days * 1440))
  );
}
type Receipt = {
  source: Source;
  generation: string;
  expires: number;
  base_url: string;
  bearer: string;
};

export function ScimEnrollment({
  user,
  revision,
  installed,
  domains,
  existing,
  disabled,
  onBusy,
  onClose,
  onChanged,
}: {
  user: User;
  revision: number;
  installed: string | null;
  domains: string[];
  existing: SavedConnection | null;
  disabled: boolean;
  onBusy: (value: boolean) => void;
  onClose: () => void;
  onChanged: () => void;
}) {
  const heading = useId();
  const [source, setSource] = useState<Source>(
    () =>
      existing?.source ?? {
        id: '',
        label: '',
        provider: 'scim',
        authority: '',
        scopes: domains.length === 1 ? [...domains] : [],
        stale_after_seconds: 86400,
      },
  );
  const [days, setDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [reveal, setReveal] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const problem = scimFormError(source, domains, days);
  useEffect(() => {
    onBusy(busy);
    return () => onBusy(false);
  }, [busy, onBusy]);
  async function enroll() {
    if (busy || disabled || problem || uncertain) return;
    setBusy(true);
    try {
      const result = await api<Receipt>(
        '/admin/identity/scim/enroll',
        {
          revision,
          catalog_sha256: installed,
          expected_generation: existing?.generation ?? null,
          source,
          expires: Math.floor(Date.now() / 1000) + days * 86400,
        },
        user.csrf,
      );
      setReceipt(result);
      onChanged();
    } catch {
      // Never replay a one-time issuance after an uncertain response. Status
      // contains only metadata; the secret cannot be recovered from it.
      setUncertain(true);
      onChanged();
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  }
  return (
    <section
      className="directory-scim directory-saved-connection"
      aria-labelledby={heading}
    >
      <header>
        <h4 id={heading}>
          {existing
            ? 'Rotate SCIM provisioning token'
            : 'Set up SCIM provisioning'}
        </h4>
        <span className="badge">Development profile · reviewed activation</span>
      </header>
      <p className="notice">
        Provisioning stages users and groups on the management server. It does
        not change mail routing or console accounts. Inspect the staged
        inventory, confirm completeness, then review and apply an immutable
        candidate. Qualify the connector with synthetic data first.
      </p>
      {receipt ? (
        <div className="directory-scim-receipt">
          <output>
            <strong>Token issued for {receipt.source.label}.</strong> Copy it
            into the intended identity provider over HTTPS. It is shown only in
            this view and cannot be retrieved later.
          </output>
          <label>
            SCIM base URL
            <input readOnly value={receipt.base_url} />
          </label>
          <label>
            Provisioning bearer token
            <input
              type={reveal ? 'text' : 'password'}
              readOnly
              value={receipt.bearer}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button
            type="button"
            className="secondary"
            aria-pressed={reveal}
            onClick={() => setReveal(!reveal)}
          >
            {reveal ? 'Hide token' : 'Reveal token'}
          </button>
          <p className="small muted">
            Expires {new Date(receipt.expires * 1000).toLocaleString('en-GB')} ·
            generation <code>{receipt.generation}</code>
          </p>
          <p className="small">
            Closing this view discards the displayed token. Rotate access if it
            is lost; revocation and rotation preserve staged identities.
          </p>
        </div>
      ) : (
        <>
          {existing && (
            <p className="notice">
              Rotating access immediately invalidates the previous token. Update
              the provider afterward. Source and domain assignments remain
              fixed.
            </p>
          )}
          <fieldset
            className="directory-sync-form"
            disabled={busy || disabled || uncertain}
          >
            <legend>Source and authorization</legend>
            <label>
              Stable source ID
              <input
                value={source.id}
                readOnly={!!existing}
                maxLength={100}
                autoComplete="off"
                onChange={(e) => setSource({ ...source, id: e.target.value })}
                placeholder="organization-scim"
              />
            </label>
            <label>
              Source name
              <input
                value={source.label}
                readOnly={!!existing}
                maxLength={200}
                onChange={(e) =>
                  setSource({ ...source, label: e.target.value })
                }
                placeholder="Organization directory"
              />
            </label>
            <label>
              Provider tenant or directory identifier
              <input
                value={source.authority}
                readOnly={!!existing}
                maxLength={256}
                onChange={(e) =>
                  setSource({ ...source, authority: e.target.value })
                }
              />
            </label>
            <fieldset disabled={!!existing}>
              <legend>Receiving domain scope</legend>
              {domains.map((domain) => (
                <label key={domain}>
                  <input
                    type="checkbox"
                    checked={source.scopes.includes(domain)}
                    onChange={(e) =>
                      setSource({
                        ...source,
                        scopes: e.target.checked
                          ? [...source.scopes, domain]
                          : source.scopes.filter((s) => s !== domain),
                      })
                    }
                  />
                  {domain}
                </label>
              ))}
            </fieldset>
            <label>
              Directory freshness limit (hours)
              <input
                type="number"
                min={1}
                max={720}
                step={1}
                readOnly={!!existing}
                value={source.stale_after_seconds / 3600}
                onChange={(e) =>
                  setSource({
                    ...source,
                    stale_after_seconds: Number(e.target.value) * 3600,
                  })
                }
              />
            </label>
            <label>
              Token lifetime (days)
              <input
                type="number"
                min={1}
                max={90}
                step={1}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              />
            </label>
            <p className="small muted">
              NoiseFence generates the token. No provider password is required.
              Access is limited to this source and expires automatically.
            </p>
          </fieldset>
          {problem && <p className="notice">{problem}</p>}
          {uncertain && (
            <p className="alert error" role="alert">
              No verified enrollment response was received. Access may have been
              created or rotated. Close this form and reload saved access. If a
              generation exists, rotate that generation explicitly; do not
              repeat the same enrollment.
            </p>
          )}
        </>
      )}
      <div className="actions">
        {!receipt && (
          <button
            type="button"
            disabled={busy || disabled || !!problem || uncertain}
            onClick={() => setConfirm(true)}
          >
            Review {existing ? 'rotation' : 'enrollment'}
          </button>
        )}
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={onClose}
        >
          {receipt
            ? 'Done — discard displayed token'
            : uncertain
              ? 'Close and reload status'
              : 'Cancel'}
        </button>
      </div>
      {confirm && (
        <ConfirmDialog
          title={
            existing
              ? 'Rotate provisioning access?'
              : 'Issue provisioning access?'
          }
          confirmLabel={existing ? 'Rotate token' : 'Issue token'}
          danger={!!existing}
          busy={busy}
          confirmDisabled={disabled || !!problem || uncertain}
          onCancel={() => setConfirm(false)}
          onConfirm={() => void enroll()}
        >
          <p>
            <strong>{source.label}</strong> · {source.authority}
          </p>
          <p>
            Scope: {source.scopes.join(', ')}. Lifetime: {days} days. The
            provider can create, change and delete staged identities in this
            source. It cannot activate them.
          </p>
          {existing && (
            <p>
              The previous token will stop working immediately. Staged resources
              are preserved.
            </p>
          )}
        </ConfirmDialog>
      )}
    </section>
  );
}

export type ScimInventoryView = {
  revision: number;
  catalog_sha256: string | null;
  stage: {
    revision: {
      source_id: string;
      source_sha256: string;
      enrollment: string;
      sequence: number;
    };
    users: number;
    groups: number;
    memberships: number;
    modified: number;
  };
  draft: DirectoryDraft | null;
  inventory_sha256: string | null;
  problem: string | null;
};
export function scimInventoryMatches(
  v: ScimInventoryView,
  entry: SavedConnection,
  revision: number,
  installed: string | null,
) {
  return (
    v.revision === revision &&
    v.catalog_sha256 === installed &&
    v.stage.revision.source_id === entry.source.id &&
    v.stage.revision.enrollment === entry.generation &&
    v.draft?.source.id === entry.source.id &&
    !!v.inventory_sha256 &&
    /^[0-9a-f]{64}$/.test(v.inventory_sha256) &&
    !v.problem
  );
}
/** Bounded DOM: the complete bounded inventory is available to search, 50 rows
 * per page. Provider strings remain React text, never HTML or clickable links. */
export function ScimInventoryRows({ draft }: { draft: DirectoryDraft }) {
  const [kind, setKind] = useState<'people' | 'groups' | 'memberships'>(
    'people',
  );
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const values =
    kind === 'memberships'
      ? draft.memberships.map((m) => [m.group, m.member.kind, m.member.id])
      : draft[kind].map((p) => [
          p.id,
          p.display_name,
          p.activity,
          p.addresses.join(', '),
        ]);
  const found = values.filter((row) =>
    row.some((s) => s.toLocaleLowerCase().includes(query.toLocaleLowerCase())),
  );
  const pages = Math.max(1, Math.ceil(found.length / 50));
  const current = Math.min(page, pages - 1);
  return (
    <section aria-label="Staged inventory records">
      <div className="directory-sync-form">
        <label>
          Records
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as typeof kind);
              setPage(0);
            }}
          >
            <option value="people">People</option>
            <option value="groups">Groups</option>
            <option value="memberships">Memberships</option>
          </select>
        </label>
        <label>
          Search inventory
          <input
            value={query}
            maxLength={200}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
          />
        </label>
      </div>
      <div className="directory-scim-table">
        <table>
          <thead>
            <tr>
              {(kind === 'memberships'
                ? ['Group ID', 'Member type', 'Member ID']
                : ['ID', 'Display name', 'State', 'Addresses']
              ).map((t) => (
                <th key={t} scope="col">
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {found.slice(current * 50, (current + 1) * 50).map((row, i) => (
              <tr key={current * 50 + i}>
                {row.map((cell, j) => (
                  <td key={j}>{cell || '—'}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={current === 0}
          onClick={() => setPage(current - 1)}
        >
          Previous records
        </button>
        <span>
          {found.length} {found.length === 1 ? 'record' : 'records'} · Page{' '}
          {current + 1} / {pages}
        </span>
        <button
          type="button"
          className="secondary"
          disabled={current + 1 >= pages}
          onClick={() => setPage(current + 1)}
        >
          Next records
        </button>
      </div>
    </section>
  );
}
export function ScimInventory({
  user,
  entry,
  revision,
  installed,
  disabled,
  onBusy,
  onClose,
  onReceipt,
}: {
  user: User;
  entry: SavedConnection;
  revision: number;
  installed: string | null;
  disabled: boolean;
  onBusy: (busy: boolean) => void;
  onClose: () => void;
  onReceipt: (id: string) => void;
}) {
  const [view, setView] = useState<ScimInventoryView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [attested, setAttested] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [attempt, setAttempt] = useState('');
  const valid = view && scimInventoryMatches(view, entry, revision, installed);
  useEffect(() => {
    onBusy(busy);
    return () => onBusy(false);
  }, [busy, onBusy]);
  async function load() {
    if (busy || disabled || attempt) return;
    setBusy(true);
    setError('');
    setView(null);
    setAttested(false);
    try {
      setView(
        await api<ScimInventoryView>(
          '/admin/identity/scim/inventory',
          { source_id: entry.source.id, generation: entry.generation },
          user.csrf,
        ),
      );
    } catch {
      setError(
        'Inventory unavailable. Check saved access and reload; no completeness attestation was recorded.',
      );
    } finally {
      setBusy(false);
    }
  }
  async function attest() {
    if (!view || !valid || !attested || disabled || busy || attempt) return;
    const operation = crypto.randomUUID();
    setAttempt(operation);
    onReceipt(operation);
    setBusy(true);
    setError('');
    try {
      await api(
        '/admin/identity/scim/attest',
        {
          operation,
          revision,
          catalog_sha256: installed,
          connection: {
            source_id: entry.source.id,
            generation: entry.generation,
          },
          staged_revision: view.stage.revision,
          inventory_sha256: view.inventory_sha256,
          complete_inventory: true,
        },
        user.csrf,
      );
    } catch {
      setError(
        'No verified response. Inspect the preparation receipt below before another attempt. The request will not be replayed.',
      );
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  }
  return (
    <section
      className="directory-saved-connection"
      aria-label="SCIM inventory review"
    >
      <h4>Review staged inventory · {entry.source.label}</h4>
      <p className="notice">
        SCIM does not report when a full synchronization is complete. Check the
        provider job and the full inventory before attesting. A last update
        timestamp is not proof of completeness.
      </p>
      <div className="actions">
        <button
          type="button"
          disabled={disabled || busy || !!attempt}
          onClick={() => void load()}
        >
          {busy ? 'Working…' : 'Load current inventory'}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={onClose}
        >
          Close inventory
        </button>
      </div>
      {error && (
        <p role="alert" className="alert error">
          {error}
        </p>
      )}
      {view && (
        <>
          <p>
            {view.stage.users} {view.stage.users === 1 ? 'person' : 'people'} ·{' '}
            {view.stage.groups} {view.stage.groups === 1 ? 'group' : 'groups'} ·{' '}
            {view.stage.memberships} memberships
          </p>
          <p className="small muted">
            Last staged change:{' '}
            {new Date(view.stage.modified * 1000).toLocaleString('en-GB')} ·
            sequence {view.stage.revision.sequence}. Loading this view does not
            activate changes.
          </p>
          {view.problem && <p className="alert error">{view.problem}</p>}
          {view.draft && (
            <ScimInventoryRows key={view.inventory_sha256} draft={view.draft} />
          )}
          <details>
            <summary>Inventory provenance</summary>
            <p>
              SHA-256 <code>{view.inventory_sha256 ?? 'Unavailable'}</code>
            </p>
            <p>
              Access generation <code>{view.stage.revision.enrollment}</code>
            </p>
            <p>Based on policy revision {view.revision}.</p>
          </details>
          {!valid && !view.problem && (
            <p className="notice">
              The policy or access generation changed. Reload saved access and
              the inventory.
            </p>
          )}
          <label>
            <input
              type="checkbox"
              checked={attested}
              disabled={!valid || busy || disabled || !!attempt}
              onChange={(e) => setAttested(e.target.checked)}
            />{' '}
            I checked the provider job and confirm this is the complete intended
            inventory, including any removals.
          </label>
          <div className="actions">
            <button
              type="button"
              disabled={!valid || !attested || busy || disabled || !!attempt}
              onClick={() => setConfirm(true)}
            >
              Review completeness attestation
            </button>
          </div>
        </>
      )}
      {attempt && (
        <p className="notice">
          Preparation receipt: <code>{attempt}</code>. Inspect its result below.
          Review the diff and apply the policy separately; nothing is activated
          by this action.
        </p>
      )}
      {confirm && (
        <ConfirmDialog
          title="Confirm complete SCIM inventory?"
          confirmLabel="Attest and prepare candidate"
          busy={busy}
          confirmDisabled={!valid || !attested || disabled || !!attempt}
          onCancel={() => setConfirm(false)}
          onConfirm={() => void attest()}
        >
          <p>
            Prepare exactly the displayed inventory of {view?.stage.users}{' '}
            people and {view?.stage.groups} groups for {entry.source.label}. A
            concurrent provisioning update or access rotation will invalidate
            this attempt. Existing protected-role assignments are preserved for
            surviving identities. Removed identities and assignments require
            review.
          </p>
          <p>
            This records your completeness attestation. It does not apply the
            candidate or change mail routing, console access or the active
            policy.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
