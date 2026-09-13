'use client';
import { useEffect, useState } from 'react';
import { api } from './client';
export type AdmissionSettings = {
  enabled: boolean;
  mode: 'observe' | 'enforce';
  greylisting: boolean;
  minimum_providers: number;
  allow_networks: string[];
  rate_per_minute: number;
  rate_burst: number;
  retry_delay_seconds: number;
  retry_max_age_seconds: number;
  retention_seconds: number;
  max_entries: number;
  tarpit_delay_ms: number;
  tarpit_max_concurrent: number;
  tarpit_session_budget_ms: number;
};
export type AdmissionDecision = {
  status: string;
  mode: string;
  reasons: string[];
  retry_after_seconds?: number | null;
  would_defer: boolean;
};
const labels: Record<string, string> = {
  disabled: "Disabled",
  exempt: 'Exception',
  not_selected: "No carry-over required",
  first_seen: "First delayed attempt",
  too_soon: "New attempt too soon",
  retry_passed: "New attempt accepted",
  passed: "Remembered retry",
  rate_limited: "Rate limit exceeded",
  capacity: "Saturated state · permitted passage",
  unavailable: "State not available · permitted passage",
  clock_skew: "Incoherent clock · permitted passage",
};
const reasons: Record<string, string> = {
  ip_reputation: "Unfavorable IP reputation",
  invalid_helo: "HELO without valid domain or IP address",
  sender_rate_exceeded: "Flow limit achieved",
  delivery_notification_or_postmaster: "Delivery notice or postmaster",
};
export function AdmissionDetails({
  reports,
}: {
  reports: AdmissionDecision[];
}) {
  return (
    <section aria-label="SMTP admission">
      <h3>SMTP admission before receipt</h3>
      <ul>
        {reports.map((r, i) => (
          <li key={i}>
            {labels[r.status] || r.status} ·{' '}
            {r.mode === 'observe' ? 'observation' : 'application'}
            {r.reasons.length > 0 &&
              ` · ${r.reasons.map((v) => reasons[v] || v).join(', ')}`}
          </li>
        ))}
      </ul>
      <p className="muted">
        These transport checks do not add any points to the antispam score.
      </p>
    </section>
  );
}
export function AdmissionEditor({
  value,
  onChange,
}: {
  value: AdmissionSettings;
  onChange: (s: AdmissionSettings) => void;
}) {
  const [report, setReport] = useState<{
    counts: { mode: string; status: string; count: number }[];
    shared: boolean;
  } | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    api<{
      counts: { mode: string; status: string; count: number }[];
      shared: boolean;
    }>('/admin/admission')
      .then(setReport)
      .catch(() => setError("Statistics temporarily unavailable."));
  }, []);
  const set = <K extends keyof AdmissionSettings>(
    key: K,
    v: AdmissionSettings[K],
  ) => onChange({ ...value, [key]: v });
  const number = (
    key: keyof AdmissionSettings,
    label: string,
    min: number,
    max: number,
    help: string,
  ) => (
    <label className="field">
      <span>{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        value={Number(value[key])}
        onChange={(e) => set(key, Number(e.target.value))}
      />
      <small>{help}</small>
    </label>
  );
  return (
    <section className="management-settings">
      <div className="management-card">
        <h2>Greylisting and transport protection</h2>
        <p>
          Ask suspicious senders to try again before receiving the body. The delay is shared between the MX; a failure of coordination lets pass the attempt.
        </p>
        <label>
          <input
            type="checkbox"
            checked={value.enabled}
            onChange={(e) => set('enabled', e.target.checked)}
          />{' '}
          Enable SMTP admission controls
        </label>
        <label className="field">
          <span>Transport mode</span>
          <select
            value={value.mode}
            onChange={(e) =>
              set('mode', e.target.value as AdmissionSettings['mode'])
            }
          >
            <option value="observe">Observe without delay</option>
            <option value="enforce">
              Apply temporary deferrals (451)
            </option>
          </select>
          <small>
            Separate from content observation. Enforcement may delay legitimate messages; it does not classify them as spam.
          </small>
        </label>
        <label>
          <input
            type="checkbox"
            checked={value.greylisting}
            onChange={(e) => set('greylisting', e.target.checked)}
          />{' '}
          Selective greylisting
        </label>
        <div className="form-grid">
          {number(
            'minimum_providers',
            "Corroborating signals required",
            2,
            8,
            "At least one positive IP list; separate operators and an invalid HELO are counted.",
          )}
          {number(
            'retry_delay_seconds',
            "Minimum time (seconds)",
            1,
            3600,
            "Early retries do not extend this delay.",
          )}
          {number(
            'retry_max_age_seconds',
            "Expiry without retry (seconds)",
            2,
            604800,
            "Must exceed the minimum time limit.",
          )}
          {number(
            'retention_seconds',
            "Remember successful retries (seconds)",
            1,
            2592000,
            "Fixed duration, not extended by traffic.",
          )}
        </div>
        <p className="muted">
          Greylisting groups retry addresses by /24 IPv4 and /64 IPv6. Null-sender notifications and postmaster recipients are exempt from greylisting, but remain subject to rate limits.
        </p>
      </div>
      <div className="management-card">
        <h3>Rate limits and response delays (teergrubing)</h3>
        <div className="form-grid">
          {number(
            'rate_per_minute',
            "Attempts per IP per minute",
            0,
            60000,
            "0 disables the quota. Shared across MX servers; IPv6 addresses are grouped by /64.",
          )}
          {number(
            'rate_burst',
            "Allowed burst",
            1,
            10000,
            "Number of attempts available immediately.",
          )}
          {number(
            'tarpit_delay_ms',
            "Delay before a 451 response (ms)",
            0,
            5000,
            "0 disables the delay. Only applies before a temporary deferral.",
          )}
          {number(
            'tarpit_session_budget_ms',
            "Maximum waiting per connection (ms)",
            0,
            10000,
            "Preserved across RSET and STARTTLS.",
          )}
          {number(
            'tarpit_max_concurrent',
            "Concurrent delayed connections per MX",
            1,
            64,
            "Saturation removes the additional wait.",
          )}
          {number(
            'max_entries',
            "State capacity per node",
            1,
            100000,
            "Active retry states are never ousted.",
          )}
        </div>
      </div>
      <div className="management-card">
        <h3>Confidence exceptions</h3>
        <label className="field">
          <span>IP/CIDR networks, one per line</span>
          <textarea
            rows={4}
            key={value.allow_networks.join('\n')}
            defaultValue={value.allow_networks.join('\n')}
            onBlur={(e) =>
              set(
                'allow_networks',
                e.target.value
                  .split('\n')
                  .map((v) => v.trim())
                  .filter(Boolean),
              )
            }
            placeholder={'192.0.2.10/32\n2001:db8::/64'}
          />
          <small>
            Free these IPs from the greylisting and quota. No declared domain or sender is enough to get an exception.
          </small>
        </label>
      </div>
      <div className="management-card">
        <h3>Last 30 days&apos; decisions</h3>
        {error && <output>{error}</output>}
        {report && (
          <>
            <p>
              {report.shared ? "Common state of MX" : "Status of this server"} · attempt counters, not unique messages.
            </p>
            {report.counts.length ? (
              <ul>
                {report.counts.map((r) => (
                  <li key={r.mode + r.status}>
                    {labels[r.status] || r.status} ·{' '}
                    {r.mode === 'observe' ? 'observation' : 'application'} :{' '}
                    <strong>{r.count}</strong>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No attempt at this time.</p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
