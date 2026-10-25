import { useEffect, useId, useState } from 'react';
import { api, type User } from './client';
import { ConfirmDialog } from './console-ui';
import { sourceError, type Source } from './directory';
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
        <span className="badge">Development profile · staging only</span>
      </header>
      <p className="notice">
        Provisioning stages users and groups on the management server. It does
        not change mail routing, console accounts or filtering. Inventory
        attestation and activation are not yet available for this connector;
        qualify it with synthetic data first.
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
