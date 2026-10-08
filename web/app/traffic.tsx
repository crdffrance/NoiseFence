'use client';
import { useState } from 'react';
export type TrafficPolicy = {
  action: 'observe' | 'defer' | 'quarantine';
  window_seconds: number;
  sender_limit: number;
  domain_limit: number;
  recipient_limit: number;
  duplicate_limit: number;
  verify_new_senders: boolean;
  trusted_senders: string[];
};
export type TrafficSettings = {
  enabled: boolean;
  policy: TrafficPolicy;
  scopes: Record<string, TrafficPolicy>;
  allow_personal: boolean;
  verification: {
    enabled: boolean;
    public_origin: string;
    site_key: string;
    notification_from: string;
    relay_hosts: string[];
    lifetime_hours: number;
    remember_days: number;
    invitations_per_day: number;
  };
};
export type TrafficReport = {
  status: string;
  action: string;
  enforced: boolean;
  reasons: string[];
  window_seconds: number;
  counts: Record<string, number>;
  verification_id?: string;
};
export const defaultTrafficPolicy: TrafficPolicy = {
  action: 'observe',
  window_seconds: 300,
  sender_limit: 60,
  domain_limit: 300,
  recipient_limit: 300,
  duplicate_limit: 20,
  verify_new_senders: false,
  trusted_senders: [],
};
const defaults: TrafficSettings = {
  enabled: false,
  policy: defaultTrafficPolicy,
  scopes: {},
  allow_personal: false,
  verification: {
    enabled: false,
    public_origin: '',
    site_key: '',
    notification_from: '',
    relay_hosts: [],
    lifetime_hours: 24,
    remember_days: 30,
    invitations_per_day: 100,
  },
};
export function TrafficPolicyEditor({
  value,
  onChange,
}: {
  value: TrafficPolicy;
  onChange: (v: TrafficPolicy) => void;
}) {
  const limits = [
    ['window_seconds', 'Window (seconds)', 10, 3600],
    ['sender_limit', 'Messages from one sender', 0, 100000],
    ['domain_limit', 'Messages from one sender domain', 0, 100000],
    ['recipient_limit', 'Messages to this recipient', 0, 100000],
    ['duplicate_limit', 'Messages with an identical body', 0, 100000],
  ] as const;
  return (
    <>
      <div className="form-grid">
        <label className="field">
          When a limit is exceeded
          <select
            value={value.action}
            onChange={(e) =>
              onChange({
                ...value,
                action: e.target.value as TrafficPolicy['action'],
              })
            }
          >
            <option value="observe">Observe only</option>
            <option value="defer">Defer temporarily (SMTP 451)</option>
            <option value="quarantine">Hold in quarantine</option>
          </select>
        </label>
        {limits.map(([key, label, min, max]) => (
          <label className="field" key={key}>
            {label}
            <input
              type="number"
              min={min}
              max={max}
              value={value[key]}
              onChange={(e) =>
                onChange({ ...value, [key]: Number(e.target.value) })
              }
            />
          </label>
        ))}
      </div>
      <p className="muted">
        Limits are shared across MX servers and counted per recipient. Zero
        disables a quota. Unauthenticated sender identities are scoped to their
        source IP (/64 for IPv6). Repeated deliveries and SMTP retries count as
        attempts. A temporary deferral applies to the entire SMTP transaction.
      </p>
      <label className="field">
        Authenticated sender exceptions (one address per line)
        <textarea
          value={(value.trusted_senders ?? []).join('\n')}
          onChange={(e) =>
            onChange({
              ...value,
              trusted_senders: e.target.value
                .split('\n')
                .map((v) => v.trim())
                .filter(Boolean),
            })
          }
        />
        <small>
          Only honored after SMTP authentication. Recipient-wide flood limits
          and content security checks still apply.
        </small>
      </label>
      <label>
        <input
          type="checkbox"
          checked={value.verify_new_senders}
          onChange={(e) =>
            onChange({ ...value, verify_new_senders: e.target.checked })
          }
        />{' '}
        Request verification from eligible new senders
      </label>
    </>
  );
}
export function TrafficEditor({
  value,
  onChange,
}: {
  value?: TrafficSettings | null;
  onChange: (v: TrafficSettings) => void;
}) {
  const v = value ?? defaults;
  const [scope, setScope] = useState('');
  const verification = v.verification;
  const setVerification = (change: Partial<TrafficSettings['verification']>) =>
    onChange({ ...v, verification: { ...verification, ...change } });
  return (
    <section className="management-settings">
      <div className="management-card">
        <h2>Flood protection and sender verification</h2>
        <p>
          Transport actions never change Spam, Ham or Pub scores. Content
          observation prevents deferral, quarantine and verification
          invitations.
        </p>
        <label>
          <input
            type="checkbox"
            checked={v.enabled}
            onChange={(e) => onChange({ ...v, enabled: e.target.checked })}
          />{' '}
          Enable shared traffic controls
        </label>
        <TrafficPolicyEditor
          value={v.policy}
          onChange={(policy) => onChange({ ...v, policy })}
        />
        <label>
          <input
            type="checkbox"
            checked={v.allow_personal}
            onChange={(e) =>
              onChange({ ...v, allow_personal: e.target.checked })
            }
          />{' '}
          Allow mailbox owners to customize their traffic policy
        </label>
      </div>
      <div className="management-card">
        <h3>Recipient and domain overrides</h3>
        <p className="muted">
          Exact recipient settings take precedence over *@domain settings, then
          defaults. Authorized personal settings take precedence when delegation
          is enabled.
        </p>
        {Object.entries(v.scopes).map(([key, policy]) => (
          <details key={key}>
            <summary>{key}</summary>
            <TrafficPolicyEditor
              value={policy}
              onChange={(next) =>
                onChange({ ...v, scopes: { ...v.scopes, [key]: next } })
              }
            />
            <button
              type="button"
              onClick={() => {
                const scopes = { ...v.scopes };
                delete scopes[key];
                onChange({ ...v, scopes });
              }}
            >
              Remove override
            </button>
          </details>
        ))}
        <label className="field">
          Address or *@domain
          <input
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="*@example.org"
          />
        </label>
        <button
          type="button"
          disabled={!scope.trim() || !!v.scopes[scope.trim().toLowerCase()]}
          onClick={() => {
            onChange({
              ...v,
              scopes: {
                ...v.scopes,
                [scope.trim().toLowerCase()]: { ...v.policy },
              },
            });
            setScope('');
          }}
        >
          Add override
        </button>
      </div>
      <div className="management-card">
        <h3>Sender verification service · optional</h3>
        <p>
          Eligible authenticated Ham is held per recipient. Automated mail,
          mailing lists, uncertain analyses and detected threats are excluded. A
          CAPTCHA never overrides another quarantine policy. No invitation is
          sent until the held message is durably stored, including required
          replication.
        </p>
        <label>
          <input
            type="checkbox"
            checked={verification.enabled}
            onChange={(e) => setVerification({ enabled: e.target.checked })}
          />{' '}
          Enable verification service
        </label>
        <div className="form-grid">
          {(
            [
              ['public_origin', 'Console HTTPS origin'],
              ['site_key', 'Cloudflare Turnstile site key'],
              ['notification_from', 'Notification From address'],
            ] as const
          ).map(([key, label]) => (
            <label className="field" key={key}>
              {label}
              <input
                value={verification[key]}
                onChange={(e) => setVerification({ [key]: e.target.value })}
              />
            </label>
          ))}
          {(
            [
              ['lifetime_hours', 'Link lifetime (hours)', 1, 72],
              ['remember_days', 'Remember verified sender (days)', 1, 90],
              [
                'invitations_per_day',
                'Global invitations per rolling day',
                1,
                1000,
              ],
            ] as const
          ).map(([key, label, min, max]) => (
            <label className="field" key={key}>
              {label}
              <input
                type="number"
                min={min}
                max={max}
                value={verification[key]}
                onChange={(e) =>
                  setVerification({ [key]: Number(e.target.value) })
                }
              />
            </label>
          ))}
        </div>
        <label className="field">
          Explicit outbound relay hosts (one per line)
          <textarea
            value={verification.relay_hosts.join('\n')}
            onChange={(e) =>
              setVerification({
                relay_hosts: e.target.value
                  .split('\n')
                  .map((v) => v.trim())
                  .filter(Boolean),
              })
            }
          />
        </label>
        <p className="muted">
          Requires an IP-authorized outbound relay with verified TLS; SMTP AUTH
          is not supported for invitations. Configure the private Turnstile
          secret in Provider credentials. Invitation frequency is additionally
          capped at one per sender per rolling day. A failed/uncertain
          invitation is not resent automatically; recipients can release held
          mail manually.
        </p>
      </div>
    </section>
  );
}
export function TrafficDetails({ report }: { report: TrafficReport }) {
  return (
    <section aria-label="Traffic protection">
      <h3>Traffic protection</h3>
      <p>
        <strong>{report.status.replaceAll('_', ' ')}</strong> ·{' '}
        {report.enforced ? 'Applied' : 'Observation / no transport action'} ·{' '}
        {report.action}
      </p>
      {report.reasons.length > 0 && (
        <p>{report.reasons.map((v) => v.replaceAll('_', ' ')).join(', ')}</p>
      )}
      <dl>
        {Object.entries(report.counts).map(([name, count]) => (
          <div key={name}>
            <dt>
              {name} attempts / {report.window_seconds}s
            </dt>
            <dd>{count}</dd>
          </div>
        ))}
      </dl>
      {report.verification_id && (
        <p>
          Held for sender verification. Manual release remains available in
          delivery controls.
        </p>
      )}
      <p className="muted">
        These transport checks do not contribute to the content score.
      </p>
    </section>
  );
}
