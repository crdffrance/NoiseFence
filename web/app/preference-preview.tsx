import { useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { orderingDescription } from './policy-trace';
import type { DeliveryAction } from './actions';

type Source = {
  name: string;
  scope: string | null;
  origin: 'personal' | 'administrator' | null;
};
type PolicyView = {
  ordering: 'scoped' | 'legacy_priority';
  personal_enabled: boolean;
  threshold: number | null;
  threshold_source: Source;
  threshold_locked: boolean;
  action_source: Source;
  spam: DeliveryAction;
  publicity: DeliveryAction;
  unassessed: DeliveryAction;
  quarantine_days: number;
  require_corroboration: boolean;
  profiles: { source: Source; threshold: number | null; selected: boolean }[];
  rules: {
    name: string;
    scope: string;
    origin: 'personal' | 'administrator';
    priority: number;
    stop: boolean;
  }[];
  traffic: null | {
    action: string;
    window_seconds: number;
    sender_limit: number;
    domain_limit: number;
    recipient_limit: number;
    duplicate_limit: number;
    verify_new_senders: boolean;
    trusted_sender_count: number;
  };
};
export type PreferencePreview = {
  schema: 'preference-preview-1';
  revision: number;
  checked_at: number;
  scope: string;
  recipient: string;
  mode: string;
  removing: boolean;
  installed: PolicyView;
  draft: PolicyView;
};
const source = (s: Source) =>
  [
    s.name,
    s.scope,
    s.origin === 'personal'
      ? 'Personal'
      : s.origin === 'administrator'
        ? 'Administrator'
        : null,
  ]
    .filter(Boolean)
    .join(' · ');
const action = (a: DeliveryAction) =>
  a === 'tag' ? 'Tag' : a === 'quarantine' ? 'Quarantine' : 'Deliver';
const threshold = (v: PolicyView) =>
  v.threshold_locked
    ? 'Managed by the active fusion model'
    : v.threshold == null
      ? 'Unavailable'
      : `${v.threshold.toFixed(1)} / 100`;
export function PreferencePreviewView({
  value,
  stale,
  canApply,
  busy,
  onApply,
  onClose,
}: {
  value: PreferencePreview;
  stale: boolean;
  canApply: boolean;
  busy: boolean;
  onApply: () => void;
  onClose: () => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [value]);
  if (value.schema !== 'preference-preview-1')
    return (
      <p role="alert">This preference preview requires a compatible console.</p>
    );
  const before = value.installed,
    after = value.draft;
  const rows: [string, string, string][] = [
    ['Content threshold', threshold(before), threshold(after)],
    [
      'Threshold source',
      source(before.threshold_source),
      source(after.threshold_source),
    ],
    [
      'Action source',
      source(before.action_source),
      source(after.action_source),
    ],
    ['Spam mapping', action(before.spam), action(after.spam)],
    ['Pub mapping', action(before.publicity), action(after.publicity)],
    ['Unassessed mapping', action(before.unassessed), action(after.unassessed)],
    [
      'Quarantine retention',
      `${before.quarantine_days} days`,
      `${after.quarantine_days} days`,
    ],
    [
      'Corroboration required',
      before.require_corroboration ? 'Yes' : 'No',
      after.require_corroboration ? 'Yes' : 'No',
    ],
    [
      'Applicable rules',
      String(before.rules.length),
      String(after.rules.length),
    ],
  ];
  if (before.traffic || after.traffic) {
    const summarize = (v: PolicyView) => {
      const t = v.traffic;
      return t
        ? `${t.action} · ${t.window_seconds}s window · sender ${t.sender_limit}, domain ${t.domain_limit}, recipient ${t.recipient_limit}, duplicates ${t.duplicate_limit} · new-sender verification ${t.verify_new_senders ? 'on' : 'off'} · ${t.trusted_sender_count} authenticated sender exceptions`
        : 'Disabled';
    };
    rows.push(['Traffic policy', summarize(before), summarize(after)]);
  }
  return (
    <section
      className="management-card preference-preview"
      aria-label="Preference review"
    >
      <h2 ref={heading} tabIndex={-1}>
        {value.removing
          ? 'Review restored inheritance'
          : 'Review effective preferences'}
      </h2>
      <p>
        <strong>{value.recipient}</strong> · edited scope{' '}
        <code>{value.scope}</code> · revision {value.revision}
      </p>
      <p className="muted small">{orderingDescription(after.ordering)}</p>
      {value.scope.startsWith('*@') && (
        <p className="notice">
          This result applies to the chosen original recipient. Other addresses
          or aliases may have different, more specific policies.
        </p>
      )}
      {stale && (
        <output className="notice">
          The draft, recipient or revision changed. Review again before
          applying.
        </output>
      )}
      <table
        className="preference-comparison"
        aria-label="Installed and proposed policy mappings"
      >
        <thead>
          <tr className="preference-comparison-heading">
            <th scope="col">Setting</th>
            <th scope="col">Installed</th>
            <th scope="col">Proposed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, old, next]) => (
            <tr
              key={label}
              className={old !== next ? 'preference-changed' : ''}
            >
              <th scope="row">{label}</th>
              <td>
                <small className="preference-mobile-label">Installed</small>
                {old}
              </td>
              <td>
                <small className="preference-mobile-label">Proposed</small>
                {next}
                {old !== next && (
                  <small className="preference-change-label">Changed</small>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        Profile mappings before message rules. Conditions are not evaluated
        here; administrator rules and malware protections can override them.
        Indices are not calibrated probabilities.
      </p>
      {value.mode === 'observe' && (
        <p className="notice">
          Observation remains active. Requested tags and quarantine are not
          applied by the filtering action policy.
        </p>
      )}
      {!after.personal_enabled && (
        <p className="notice">
          Personal customization is disabled. These saved personal settings are
          dormant.
        </p>
      )}
      <details>
        <summary>Proposed inheritance and rule order</summary>
        <h3>Profiles, most specific first</h3>
        <ol>
          {after.profiles.map((p, i) => (
            <li key={i}>
              {source(p.source)}
              {p.selected ? ' · selects actions' : ''} ·{' '}
              {p.threshold == null
                ? 'inherits threshold'
                : `threshold ${p.threshold}`}
            </li>
          ))}
        </ol>
        {!after.profiles.length && <p>Global defaults apply.</p>}
        <h3>Applicable rules</h3>
        <ol>
          {after.rules.map((r, i) => (
            <li key={i}>
              {r.name} · {r.scope} · {r.origin} · priority {r.priority}
              {r.stop ? ' · stops later rules if matched' : ''}
            </li>
          ))}
        </ol>
        {!after.rules.length && <p>No active rules apply to this recipient.</p>}
        <p className="muted small">
          Disabled, expired and unrelated rules are excluded at the review time.
          Rule values and message content are not exposed.
        </p>
      </details>
      <p className="muted small">
        No settings or messages have been changed by this review. Applying
        creates a checked configuration revision; follow activation status for
        every MX. Administrators can inspect the revision and audit history.
        Existing messages retain their receipt-time policy.
      </p>
      <div className="feedback-actions">
        <Button disabled={busy || stale || !canApply} onClick={onApply}>
          {busy
            ? 'Saving…'
            : value.removing
              ? 'Apply restored inheritance'
              : 'Apply reviewed preferences'}
        </Button>
        <Button variant="outline" disabled={busy} onClick={onClose}>
          Close review
        </Button>
      </div>
    </section>
  );
}
