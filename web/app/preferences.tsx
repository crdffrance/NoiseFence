'use client';
import { useEffect, useRef, useState } from 'react';
import { Plus, Trash2, Save, RotateCcw, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api, type User } from './client';
import { ActivationPanel, useActivation } from './activation-view';
import { saveNotice, savesBlocked, type SaveResult } from './activation';
import { ConfirmDialog } from './console-ui';
import {
  PreferencePreviewView,
  type PreferencePreview,
} from './preference-preview';
import { orderingDescription } from './policy-trace';
import { TrafficPolicyEditor, defaultTrafficPolicy } from './traffic';
import type { Preferences, Preference } from './management';
import type { CustomPolicy, Profile } from './custom-filtering';
type Rule = CustomPolicy['rules'][number];
type View = {
  defaults: Record<string, Profile>;
  revision: number;
  settings: Preferences;
  scopes: string[];
  mode: string;
  sensitivity_locked: boolean;
  personal_traffic: boolean;
  ordering: 'scoped' | 'legacy_priority';
};
const fields: Record<Rule['conditions'][number]['field'], string> = {
  envelope_from: 'Envelope sender',
  from_domain: 'Sender domain',
  header_from: 'From address',
  subject: 'Subject',
  body: 'Message text',
  recipient: 'Recipient',
  recipient_domain: 'Recipient domain',
  size: 'Size (bytes)',
  score: 'Score',
  category: 'Category',
  signal: 'Engine signal',
  dmarc: 'DMARC',
};
const ops: Record<Rule['conditions'][number]['op'], string> = {
  equals: 'Equal to',
  contains: 'Contains',
  starts_with: 'Starts with',
  ends_with: 'Ends with',
  present: 'Present',
  absent: 'Absent',
  at_least: 'At least',
  at_most: 'At most',
};
const actions = {
  deliver: 'Deliver',
  tag: 'Tag [SPAM] / [PUB]',
  quarantine: 'Quarantine',
};
export function MyFilters({
  user,
  onDirty,
  onBusy,
}: {
  user: User;
  onDirty: (dirty: boolean) => void;
  onBusy: (busy: boolean) => void;
}) {
  const activation = useActivation(user, false);
  const blocked = savesBlocked(activation.view, activation.error);
  const [view, setView] = useState<View | null>(null);
  const [scope, setScope] = useState('');
  const [draft, setDraft] = useState<Preference>({ profile: null, rules: [] });
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const customizeControl = useRef<HTMLInputElement>(null);
  const saveNoticeRef = useRef<HTMLOutputElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const reviewButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  useEffect(() => {
    if (notice) saveNoticeRef.current?.focus();
  }, [notice]);
  const [pendingScope, setPendingScope] = useState<string | null>(null);
  const [pendingReload, setPendingReload] = useState(false);
  const [refreshRequired, setRefreshRequired] = useState(false);
  const [addressInput, setAddressInput] = useState('');
  const [recipient, setRecipient] = useState('');
  const [review, setReview] = useState<{
    key: string;
    value: PreferencePreview;
  } | null>(null);
  const previewRecipient = scope.startsWith('*@')
    ? recipient
        .trim()
        .replace(/@([^@]+)$/, (_, domain: string) => '@' + domain.toLowerCase())
    : scope;
  const reviewKey = JSON.stringify({
    revision: view?.revision,
    scope,
    recipient: previewRecipient,
    draft,
  });
  const reviewFresh =
    review?.key === reviewKey &&
    !refreshRequired &&
    activation.view?.installed_revision === view?.revision;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    onBusy(busy);
    return () => onBusy(false);
  }, [busy, onBusy]);
  const saved = view?.settings.mailboxes[scope] ?? { profile: null, rules: [] };
  const dirty =
    !!view &&
    !refreshRequired &&
    JSON.stringify(saved) !== JSON.stringify(draft);
  useEffect(() => {
    let active = true;
    api<View>('/preferences')
      .then((v) => {
        if (active) {
          setView(v);
          const s = v.scopes[0] ?? '';
          setScope(s);
          setAddressInput(s.startsWith('*@') ? '' : s);
          setDraft(v.settings.mailboxes[s] ?? { profile: null, rules: [] });
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [user.username]);
  useEffect(() => {
    onDirty(dirty);
    const leave = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener('beforeunload', leave);
    return () => {
      window.removeEventListener('beforeunload', leave);
      onDirty(false);
    };
  }, [dirty, onDirty]);
  function switchScope(s: string) {
    setScope(s);
    setDraft(view?.settings.mailboxes[s] ?? { profile: null, rules: [] });
    setRecipient('');
    setReview(null);
    setNotice('');
    setError('');
    setAddressInput(s.startsWith('*@') ? '' : s);
  }
  function choose(s: string) {
    if (busy || refreshRequired || s === scope) return;
    if (dirty) {
      setPendingScope(s);
      return;
    }
    switchScope(s);
  }
  async function inspect(reset = false, display = true) {
    if (!view || busy || !scope || !previewRecipient || refreshRequired) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<PreferencePreview>(
        '/preferences/preview',
        {
          revision: view.revision,
          scope,
          recipient: previewRecipient,
          preference: reset ? null : draft,
        },
        user.csrf,
      );
      if (
        result.schema !== 'preference-preview-1' ||
        result.revision !== view.revision ||
        result.scope !== scope ||
        result.recipient !== previewRecipient
      )
        throw new Error(
          'The review does not match this draft. Reload preferences and try again.',
        );
      if (mounted.current) {
        if (display) setReview({ key: reviewKey, value: result });
        return result;
      }
    } catch (e) {
      if (mounted.current) {
        setReview(null);
        setError((e as Error).message);
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function enableProfile() {
    const result = await inspect(false, false);
    if (!result || !mounted.current) return;
    setReview(null);
    requestAnimationFrame(() => {
      if (mounted.current) customizeControl.current?.focus();
    });
    const p = result.draft;
    setDraft((previous) => ({
      ...previous,
      profile: {
        id: 'personal',
        name: 'Personal preferences',
        threshold: null,
        require_corroboration: true,
        spam: p.spam,
        publicity: p.publicity,
        review: p.unassessed,
        quarantine_days: p.quarantine_days,
      },
    }));
  }
  async function save() {
    if (
      !view ||
      blocked ||
      busy ||
      !reviewFresh ||
      !review ||
      !view.settings.enabled
    )
      return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<SaveResult>(
        '/preferences',
        {
          revision: view.revision,
          scope,
          preference: review.value.removing ? null : draft,
        },
        user.csrf,
      );
      if (!mounted.current) return;
      setReview(null);
      setNotice(saveNotice(result));
      setRefreshRequired(true);
      await activation.refresh();
      try {
        const next = await api<View>('/preferences');
        if (!mounted.current) return;
        setView(next);
        setDraft(
          next.settings.mailboxes[scope] ?? { profile: null, rules: [] },
        );
        setRefreshRequired(false);
      } catch (e) {
        if (mounted.current)
          setError(
            `Save acknowledged, but installed preferences could not be refreshed. Reload before editing again. ${(e as Error).message}`,
          );
      }
    } catch (e) {
      if (mounted.current) {
        setReview(null);
        setError((e as Error).message);
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function reload() {
    if (busy) return;
    setBusy(true);
    setPendingReload(false);
    try {
      const next = await api<View>('/preferences');
      if (!mounted.current) return;
      setView(next);
      setDraft(next.settings.mailboxes[scope] ?? { profile: null, rules: [] });
      setReview(null);
      setError('');
      setRefreshRequired(false);
      setNotice('Installed preferences reloaded.');
    } catch (e) {
      if (mounted.current) setError((e as Error).message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  const installedRevision = activation.view?.installed_revision;
  const pendingActivation = activation.view?.pending;
  const currentRevision = view?.revision;
  useEffect(() => {
    if (
      currentRevision === undefined ||
      dirty ||
      busy ||
      refreshRequired ||
      installedRevision === undefined ||
      pendingActivation ||
      installedRevision === currentRevision
    )
      return;
    let active = true;
    api<View>('/preferences')
      .then((next) => {
        if (active) {
          setView(next);
          setDraft(
            next.settings.mailboxes[scope] ?? { profile: null, rules: [] },
          );
          setNotice('Installed preferences refreshed.');
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [
    installedRevision,
    currentRevision,
    pendingActivation,
    dirty,
    busy,
    scope,
    refreshRequired,
  ]);
  function rule(i: number, p: Partial<Rule>) {
    setDraft({
      ...draft,
      rules: draft.rules.map((r, n) => (n === i ? { ...r, ...p } : r)),
    });
  }
  return (
    <div className="management-settings personal-filters">
      {pendingScope !== null && (
        <ConfirmDialog
          title="Discard unsaved filter changes?"
          confirmLabel="Discard and change scope"
          danger
          busy={busy}
          onCancel={() => {
            setPendingScope(null);
            setAddressInput(scope.startsWith('*@') ? '' : scope);
          }}
          onConfirm={() => {
            switchScope(pendingScope);
            setPendingScope(null);
          }}
        >
          <p>
            Only the current draft will be discarded. Installed policies and
            delivered messages stay unchanged.
          </p>
        </ConfirmDialog>
      )}
      {pendingReload && (
        <ConfirmDialog
          title="Reload installed preferences?"
          confirmLabel="Reload and discard draft"
          danger
          busy={busy}
          onCancel={() => setPendingReload(false)}
          onConfirm={() => void reload()}
        >
          <p>
            Your current draft will be discarded only after installed
            preferences can be loaded.
          </p>
        </ConfirmDialog>
      )}
      <ActivationPanel state={activation} user={user} />
      <div className="page-title">
        <p className="eyebrow">PERSONAL SPACE</p>
        <h1>
          <SlidersHorizontal size={26} /> My filters
        </h1>
        <p>
          Choose sensitivity and actions for your addresses, then refine with
          your rules.
        </p>
      </div>
      {error && (
        <p ref={errorRef} tabIndex={-1} role="alert" className="error">
          {error}{' '}
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => {
              if (dirty && !refreshRequired) setPendingReload(true);
              else void reload();
            }}
          >
            Reload
          </Button>
        </p>
      )}
      {notice && (
        <output ref={saveNoticeRef} tabIndex={-1} className="notice">
          {notice}
        </output>
      )}
      {!view ? (
        <p>Loading preferences...</p>
      ) : (
        <>
          <section className="management-card">
            <label>
              Authorized address or domain
              <select
                disabled={busy || refreshRequired}
                value={view.scopes.includes(scope) ? scope : ''}
                onChange={(e) => choose(e.target.value)}
              >
                <option value="" disabled>
                  Select a scope
                </option>
                {view.scopes.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            {view.scopes.some((s) => s.startsWith('*@')) && (
              <label>
                Or a specific address in your domain
                <input
                  disabled={busy || refreshRequired}
                  aria-label="Specific address"
                  value={addressInput}
                  onChange={(e) => setAddressInput(e.target.value)}
                  placeholder="name@example.org"
                  onBlur={(e) => {
                    if (e.target.value && e.target.value !== scope)
                      choose(
                        e.target.value
                          .trim()
                          .replace(
                            /@([^@]+)$/,
                            (_, domain: string) => '@' + domain.toLowerCase(),
                          ),
                      );
                  }}
                />
              </label>
            )}
            <p>
              Selected scope: <strong>{scope || 'No address assigned'}</strong>
            </p>
            <p>
              {orderingDescription(view.ordering)} Administrator rules and
              malware protection remain authoritative.
            </p>
            {scope.startsWith('*@') && (
              <label>
                Original recipient for this review
                <input
                  disabled={busy || refreshRequired}
                  value={recipient}
                  placeholder="mailbox@example.test"
                  onChange={(e) => setRecipient(e.target.value)}
                />
                <small>
                  Choose one accepted mailbox in this domain. The review is
                  specific to that address, including its alias policy.
                </small>
              </label>
            )}
            <Button
              variant="outline"
              disabled={busy || !scope || !previewRecipient || refreshRequired}
              ref={reviewButton}
              onClick={() => void inspect()}
            >
              Review installed and draft settings
            </Button>
            {view.mode === 'observe' && (
              <p className="notice">
                Active observation: decisions are visible in history, filtering
                action policy transmits messages without tagging or quarantine.
                Separate traffic protection and protocol checks still apply.
              </p>
            )}
          </section>
          {!view.settings.enabled && (
            <p className="notice">
              Customization is disabled by the administrator.
            </p>
          )}
          <fieldset
            disabled={
              !view.settings.enabled ||
              busy ||
              !scope ||
              blocked ||
              refreshRequired
            }
            className="personal-controls"
          >
            {view.personal_traffic && (
              <section className="management-card">
                <h3>Traffic protection</h3>
                <label>
                  <input
                    type="checkbox"
                    checked={!!draft.traffic}
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        traffic: e.target.checked
                          ? { ...defaultTrafficPolicy }
                          : null,
                      })
                    }
                  />{' '}
                  Customize traffic limits for this scope
                </label>
                {draft.traffic && (
                  <TrafficPolicyEditor
                    value={draft.traffic}
                    onChange={(traffic) => setDraft({ ...draft, traffic })}
                  />
                )}
              </section>
            )}
            <section className="management-card">
              <label className="setting-toggle">
                <input
                  type="checkbox"
                  ref={customizeControl}
                  checked={draft.profile !== null}
                  disabled={!previewRecipient}
                  onChange={(e) => {
                    if (e.target.checked) void enableProfile();
                    else setDraft({ ...draft, profile: null });
                  }}
                />
                Customize sensitivity and actions
              </label>
              {draft.profile && (
                <div className="management-grid">
                  <label>
                    Sensitivity
                    <select
                      disabled={view.sensitivity_locked}
                      value={draft.profile.threshold ?? 'inherit'}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            threshold:
                              e.target.value === 'inherit'
                                ? null
                                : Number(e.target.value),
                          },
                        })
                      }
                    >
                      <option value="inherit">
                        Inherit the next applicable threshold
                      </option>
                      {[
                        [99.5, 'Very tolerant'],
                        [98, 'Lenient'],
                        [95, 'Balanced'],
                        [90, 'Strict'],
                        [85, 'Very strict'],
                      ]
                        .filter(
                          ([n]) =>
                            Number(n) >= view.settings.minimum_threshold &&
                            Number(n) <= view.settings.maximum_threshold,
                        )
                        .map(([n, label]) => (
                          <option key={n} value={n}>
                            {label} · threshold {n}
                          </option>
                        ))}
                      {draft.profile.threshold !== null &&
                        ![99.5, 98, 95, 90, 85].includes(
                          draft.profile.threshold,
                        ) && (
                          <option value={draft.profile.threshold}>
                            Customized · {draft.profile.threshold}
                          </option>
                        )}
                    </select>
                  </label>
                  <label>
                    Custom threshold ({view.settings.minimum_threshold}–
                    {view.settings.maximum_threshold})
                    <input
                      type="number"
                      step="0.1"
                      disabled={view.sensitivity_locked}
                      min={view.settings.minimum_threshold}
                      max={view.settings.maximum_threshold}
                      value={draft.profile.threshold ?? ''}
                      placeholder="Inherit"
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            threshold:
                              e.target.value === ''
                                ? null
                                : e.target.valueAsNumber,
                          },
                        })
                      }
                    />
                  </label>
                  {(['spam', 'publicity'] as const).map((k) => (
                    <label key={k}>
                      {k === 'spam'
                        ? 'Spam detected'
                        : 'Marketing and newsletters'}
                      <select
                        value={draft.profile![k]}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            profile: { ...draft.profile!, [k]: e.target.value },
                          })
                        }
                      >
                        {!view.settings.allowed_actions.includes(
                          draft.profile![k],
                        ) && (
                          <option value={draft.profile![k]} disabled>
                            {actions[draft.profile![k]]} · administrator only —
                            choose an allowed action
                          </option>
                        )}
                        {view.settings.allowed_actions.map((a) => (
                          <option key={a} value={a}>
                            {actions[a]}
                          </option>
                        ))}
                      </select>
                    </label>
                  ))}
                  <label>
                    Quarantine retention (days)
                    <input
                      type="number"
                      min={1}
                      max={30}
                      value={draft.profile.quarantine_days}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            quarantine_days: e.target.valueAsNumber,
                          },
                        })
                      }
                    />
                  </label>
                </div>
              )}
            </section>
            <section className="management-card">
              <h2>
                My rules {draft.rules.length}/{view.settings.max_rules}
              </h2>
              <p>
                The server orders active rules according to the selected
                inheritance mode. Review the proposed order before applying.
                Settings do not change messages already delivered.
              </p>
              <Button
                variant="outline"
                disabled={draft.rules.length >= view.settings.max_rules}
                onClick={() =>
                  setDraft({
                    ...draft,
                    rules: [
                      ...draft.rules,
                      {
                        id: crypto.randomUUID(),
                        name: 'New rule',
                        enabled: true,
                        priority: draft.rules.length,
                        scope,
                        expires: null,
                        any: false,
                        conditions: [
                          { field: 'subject', op: 'contains', value: '' },
                        ],
                        category: 'spam',
                        action: view.settings.allowed_actions[0],
                        stop: false,
                      },
                    ],
                  })
                }
              >
                <Plus size={16} />
                Add rule
              </Button>
            </section>
            {draft.rules.map((r, i) => (
              <section className="management-card" key={r.id}>
                <div className="management-toolbar">
                  <label className="setting-toggle">
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      onChange={(e) => rule(i, { enabled: e.target.checked })}
                    />
                    Rule {i + 1}
                  </label>
                  <input
                    aria-label={`Name of the rule ${i + 1}`}
                    value={r.name}
                    onChange={(e) => rule(i, { name: e.target.value })}
                  />
                  <Button
                    variant="ghost"
                    aria-label={`Delete Rule ${i + 1}`}
                    onClick={() =>
                      setDraft({
                        ...draft,
                        rules: draft.rules.filter((_, n) => n !== i),
                      })
                    }
                  >
                    <Trash2 size={16} />
                  </Button>
                </div>
                <div className="management-grid">
                  <label>
                    Match
                    <select
                      value={r.any ? 'any' : 'all'}
                      onChange={(e) =>
                        rule(i, { any: e.target.value === 'any' })
                      }
                    >
                      <option value="all">All conditions</option>
                      <option value="any">At least one condition</option>
                    </select>
                  </label>
                  <label>
                    Order of priority
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      value={r.priority}
                      onChange={(e) =>
                        rule(i, { priority: e.target.valueAsNumber })
                      }
                    />
                  </label>
                  <label>
                    Optional expiry (UTC)
                    <input
                      type="date"
                      value={
                        r.expires
                          ? new Date(r.expires * 1000)
                              .toISOString()
                              .slice(0, 10)
                          : ''
                      }
                      onChange={(e) =>
                        rule(i, {
                          expires: e.target.value
                            ? Math.floor(
                                new Date(
                                  e.target.value + 'T23:59:59Z',
                                ).getTime() / 1000,
                              )
                            : null,
                        })
                      }
                    />
                  </label>
                </div>
                {r.conditions.map((c, j) => (
                  <div className="personal-condition" key={j}>
                    <label>
                      Field
                      <select
                        value={c.field}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j
                                ? {
                                    ...v,
                                    field: e.target.value as typeof c.field,
                                  }
                                : v,
                            ),
                          })
                        }
                      >
                        {Object.entries(fields).map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Comparison
                      <select
                        value={c.op}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j
                                ? { ...v, op: e.target.value as typeof c.op }
                                : v,
                            ),
                          })
                        }
                      >
                        {Object.entries(ops).map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Value
                      <input
                        disabled={c.op === 'present' || c.op === 'absent'}
                        maxLength={256}
                        value={c.value}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j ? { ...v, value: e.target.value } : v,
                            ),
                          })
                        }
                      />
                    </label>
                    <Button
                      aria-label={`Delete condition ${j + 1}`}
                      disabled={r.conditions.length <= 1}
                      variant="ghost"
                      onClick={() =>
                        rule(i, {
                          conditions: r.conditions.filter((_, n) => n !== j),
                        })
                      }
                    >
                      <Trash2 size={16} />
                    </Button>
                  </div>
                ))}
                <Button
                  variant="outline"
                  disabled={r.conditions.length >= 8}
                  onClick={() =>
                    rule(i, {
                      conditions: [
                        ...r.conditions,
                        { field: 'subject', op: 'contains', value: '' },
                      ],
                    })
                  }
                >
                  Add Condition
                </Button>
                <div className="management-grid">
                  <label>
                    Classification
                    <select
                      value={r.category ?? ''}
                      onChange={(e) =>
                        rule(i, {
                          category: (e.target.value ||
                            null) as Rule['category'],
                        })
                      }
                    >
                      <option value="">Keep classification</option>
                      <option value="spam">Spam</option>
                      <option value="publicity">Marketing</option>
                      <option value="legitimate">Legitimate</option>
                      <option value="undetermined">
                        Automatic decision by threshold (legacy rule)
                      </option>
                    </select>
                  </label>
                  <label>
                    Action
                    <select
                      value={r.action ?? ''}
                      onChange={(e) =>
                        rule(i, {
                          action: (e.target.value || null) as Rule['action'],
                        })
                      }
                    >
                      <option value="">Maintain action</option>
                      {view.settings.allowed_actions.map((a) => (
                        <option key={a} value={a}>
                          {actions[a]}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              </section>
            ))}
            <div className="personal-save">
              <span>
                {refreshRequired
                  ? 'Saved · refresh required'
                  : dirty
                    ? 'Unsaved changes'
                    : activation.view?.pending
                      ? 'Activation pending'
                      : 'Installed preferences'}
              </span>
              <Button
                variant="outline"
                disabled={!view.settings.mailboxes[scope] || !previewRecipient}
                onClick={() => void inspect(true)}
              >
                <RotateCcw size={16} />
                Review inherited settings
              </Button>
              <Button
                disabled={!dirty || !previewRecipient}
                onClick={() => void inspect()}
              >
                <Save size={16} />
                {busy ? 'Checking…' : 'Review my changes'}
              </Button>
            </div>
          </fieldset>
          {review && (
            <PreferencePreviewView
              value={review.value}
              stale={!reviewFresh}
              canApply={
                view.settings.enabled &&
                !blocked &&
                (review.value.removing || dirty)
              }
              busy={busy}
              onApply={() => void save()}
              onClose={() => {
                setReview(null);
                requestAnimationFrame(() => {
                  if (mounted.current) reviewButton.current?.focus();
                });
              }}
            />
          )}
        </>
      )}
    </div>
  );
}
