'use client';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import { checkFailure } from './presentation';
import { providerCredentialLabel, providerToggleDisabled } from './provider-credentials';
import {
  ProviderQuotas,
  type ProviderQuota,
  type QuotaUsage,
} from './provider-quotas';
import {
  UrlResolutionDetails,
  type UrlResolutionReport,
} from './url-resolution';

export type ProtectionPolicy = {
  identity: boolean;
  links: boolean;
  campaigns: boolean;
  crdf: boolean;
  virustotal: boolean;
  crdf_quota?: ProviderQuota | null;
  virustotal_quota?: ProviderQuota | null;
  follow_urls: boolean;
  protected_names: { name: string; domain: string }[];
  reply_exceptions: string[];
  link_exceptions: string[];
};
type Provider = 'crdf' | 'virustotal';
type ProviderState = {
  available: boolean;
  keys: Record<Provider, boolean>;
  loaded_keys?: Record<Provider, boolean>;
  pending_keys?: Record<Provider, boolean>;
  quotas: Record<Provider, ProviderQuota> | null;
  bootstrap_quotas: Record<Provider, ProviderQuota> | null;
  usage: Record<Provider, QuotaUsage | null>;
  capacity: {
    timeout_ms: number;
    max_parallel: number;
    max_indicators: number;
  } | null;
};
const defaults: ProtectionPolicy = {
  identity: true,
  links: true,
  campaigns: true,
  crdf: false,
  virustotal: false,
  follow_urls: false,
  protected_names: [],
  reply_exceptions: [],
  link_exceptions: [],
};
export function ProtectionSettings({
  policy,
  onChange,
  user,
}: {
  policy: ProtectionPolicy | null;
  onChange: (value: ProtectionPolicy | null) => void;
  user: User;
}) {
  const [status, setStatus] = useState<ProviderState | null>(null),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false),
    [keys, setKeys] = useState<Record<Provider, string>>({
      crdf: '',
      virustotal: '',
    });
  useEffect(() => {
    let active = true;
    api<ProviderState>('/admin/protection')
      .then((s) => {
        if (active) setStatus(s);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [user]);
  const update = (change: Partial<ProtectionPolicy>) =>
    onChange({ ...(policy || defaults), ...change });
  async function saveKey(provider: Provider) {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await api(
        `/admin/protection/keys/${provider}`,
        { key: keys[provider] },
        user.csrf,
      );
      setKeys((k) => ({ ...k, [provider]: '' }));
      setStatus(await api<ProviderState>('/admin/protection'));
      setNotice(
        "Key saved on the server. Activate the connector and then apply the settings.",
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel protection-settings">
      <h2>Complementary protection</h2>
      <p className="muted">
        Observation: These sensors explain the risks without changing the score or messages delivered.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <output className="notice">{notice}</output>}
      {!status ? (
        <p>Loading connectors...</p>
      ) : !status.available ? (
        <p>Module to install on the server.</p>
      ) : (
        <>
          <label
            className="toggle-row"
            aria-label="Enable additional protections"
          >
            <span>
              <strong>Enable additional protections</strong>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-checked={!!policy}
              checked={!!policy}
              onChange={(e) =>
                onChange(e.target.checked ? { ...defaults } : null)
              }
            />
          </label>
          {policy && (
            <>
              <div className="module-grid">
                {(
                  [
                    [
                      'identity',
                      "Identity impersonation",
                      "Similar domains, protected name and response address.",
                    ],
                    [
                      'links',
                      "Phishing Links",
                      "Deceptive destination, local base, text and QR codes.",
                    ],
                    [
                      'campaigns',
                      "Repeated campaigns",
                      "Verified feedback within the same domain, with checks for contradictory corrections.",
                    ],
                    [
                      'follow_urls',
                      "Follow the links redirects",
                      "Active HTTP requests, then checking destinations. Can count a visit or consume a single-use link. No form or JavaScript executed.",
                    ],
                  ] as const
                ).map(([key, title, description]) => (
                  <label className="toggle-row" key={key} aria-label={title}>
                    <span>
                      <strong>{title}</strong>
                      <small>{description}</small>
                    </span>
                    <input
                      type="checkbox"
                      role="switch"
                      aria-checked={policy[key]}
                      checked={policy[key]}
                      onChange={(e) => update({ [key]: e.target.checked })}
                    />
                  </label>
                ))}
              </div>
              <h3>Protected names</h3>
              <p className="small muted">
                Match each name to its usual sending domain. The receiving domains are automatically protected against similarities.
              </p>
              {policy.protected_names.map((identity, i) => (
                <div className="form-grid protection-identity" key={i}>
                  <label className="field" htmlFor={`protected-name-${i}`}>
                    Name displayed
                    <Input
                      id={`protected-name-${i}`}
                      aria-label={`Protected name ${i + 1}`}
                      value={identity.name}
                      onChange={(e) =>
                        update({
                          protected_names: policy.protected_names.map((x, j) =>
                            j === i ? { ...x, name: e.target.value } : x,
                          ),
                        })
                      }
                    />
                  </label>
                  <label className="field" htmlFor={`protected-domain-${i}`}>
                    Expected domain
                    <Input
                      id={`protected-domain-${i}`}
                      aria-label={`Protected Name Domain ${i + 1}`}
                      value={identity.domain}
                      onChange={(e) =>
                        update({
                          protected_names: policy.protected_names.map((x, j) =>
                            j === i ? { ...x, domain: e.target.value } : x,
                          ),
                        })
                      }
                    />
                  </label>
                  <Button
                    variant="ghost"
                    onClick={() =>
                      update({
                        protected_names: policy.protected_names.filter(
                          (_, j) => j !== i,
                        ),
                      })
                    }
                  >
                    Remove this name
                  </Button>
                </div>
              ))}
              <Button
                disabled={policy.protected_names.length >= 100}
                onClick={() =>
                  update({
                    protected_names: [
                      ...policy.protected_names,
                      { name: '', domain: '' },
                    ],
                  })
                }
              >
                Add a Protected Name
              </Button>
              <div className="form-grid">
                {(
                  [
                    ['reply_exceptions', "Response address exceptions"],
                    ['link_exceptions', "Exceptions for follow-up links"],
                  ] as const
                ).map(([key, title]) => (
                  <label className="field" key={key}>
                    {title}
                    <small>
                      One exact domain per line. The exception is for this verification only.
                    </small>
                    <textarea
                      rows={3}
                      spellCheck={false}
                      value={policy[key].join('\n')}
                      onChange={(e) =>
                        update({ [key]: e.target.value.split('\n') })
                      }
                    />
                  </label>
                ))}
              </div>
              <h3>Reputation services</h3>
              <p className="small muted">
                Search existing reports: CRDF domains (built HTTPS root, without path or email parameter); SHA-256 domains and fingerprints of attachments for VirusTotal. No message body, file or full link sent. Use keys licensed for this use.
              </p>
              <p className="small muted">
                Quotas are shared by the entire server. Changing them does not reset meters to zero. Even unlimited:{' '}
                {status.capacity?.max_parallel} simultaneous provider analyses,
                {status.capacity?.max_indicators} indicators by provider and message, time {status.capacity?.timeout_ms} ms per provider.
              </p>
              <Button
                type="button"
                onClick={async () => {
                  try {
                    setStatus(await api<ProviderState>('/admin/protection'));
                    setError('');
                  } catch (e) {
                    setError((e as Error).message);
                  }
                }}
              >
                Updating meters
              </Button>
              <div className="module-grid">
                {(['crdf', 'virustotal'] as const).map((provider) => (
                  <section className="module-card" key={provider}>
                    <label className="toggle-row">
                      <span>
                        <strong>
                          {provider === 'crdf'
                            ? 'CRDF Threat Center'
                            : 'VirusTotal'}
                        </strong>
                        <small>
                          {providerCredentialLabel(status.keys[provider], status.loaded_keys?.[provider], status.pending_keys?.[provider])}{' '}
                        </small>
                      </span>
                      <input
                        aria-label={`Enable ${provider}`}
                        type="checkbox"
                        role="switch"
                        aria-checked={policy[provider]}
                        checked={policy[provider]}
                        disabled={providerToggleDisabled(status.keys[provider], status.loaded_keys?.[provider], policy[provider])}
                        onChange={(e) =>
                          update({ [provider]: e.target.checked })
                        }
                      />
                    </label>
                    {status.bootstrap_quotas && (
                      <ProviderQuotas
                        name={provider === 'crdf' ? 'CRDF' : 'VirusTotal'}
                        value={policy[`${provider}_quota`]}
                        bootstrap={status.bootstrap_quotas[provider]}
                        applied={status.quotas?.[provider] ?? null}
                        usage={status.usage?.[provider]}
                        onChange={(quota) =>
                          update({ [`${provider}_quota`]: quota })
                        }
                      />
                    )}
                    <label className="field">
                      {status.keys[provider] ? "Replace key" : "API key"}
                      <Input
                        type="password"
                        autoComplete="off"
                        aria-label={`API key ${provider}`}
                        value={keys[provider]}
                        onChange={(e) =>
                          setKeys((k) => ({ ...k, [provider]: e.target.value }))
                        }
                      />
                    </label>
                    <Button
                      disabled={busy || keys[provider].length < 16}
                      onClick={() => saveKey(provider)}
                    >
                      Save Key{' '}
                      {provider === 'crdf' ? 'CRDF' : 'VirusTotal'}
                    </Button>
                    <p className="small muted">
                      Server-side key, never displayed or included in settings history.
                    </p>
                  </section>
                ))}
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
}
const statuses: Record<string, string> = {
  disabled: "Disabled",
  complete: "Complete",
  not_configured: "Not configured",
  not_run: "Not run",
  unknown: "unknown",
  limited: 'Limit reached',
  busy: "At capacity",
  unavailable: "Unavailable",
  quota: "Quota or provider cooldown",
  stale: "Stale data",
};
type ProviderReport = {
  request_count?:number;http_status_counts?:Record<string,number>;failure_counts?:Record<string,number>;retry_after_seconds?:number|null;
  failure?: string | null;
  omitted?: number;
  status: string;
  checked: number;
  malicious: number;
  suspicious: number;
  unknown: number;
  cache_hits: number;
  elapsed_ms: number;
};
export type ProtectionReport = {
  url_resolution?: UrlResolutionReport | null;
  version: string;
  observation_only: boolean;
  local_status: string;
  feed_status: string;
  campaign_status: string;
  campaign_match: boolean;
  campaign_conflict: boolean;
  authenticated_sender: boolean;
  crdf: ProviderReport;
  virustotal: ProviderReport;
  findings: {
    id: string;
    family: string;
    indicator: string;
    sources: string[];
    detail: string;
  }[];
  families: string[];
  elapsed_ms: number;
};
export function ProtectionDetails({ report }: { report: ProtectionReport }) {
  return (
    <section className="panel">
      <h2>Complementary protection</h2>
      <p className="notice">
        Observations only · {report.version} · {report.elapsed_ms} ms. Correlated detections are grouped and do not change the current score. Several services reporting the same indicator do not constitute independent votes.
      </p>
      <div className="form-grid">
        <p>
          Local checks: {statuses[report.local_status]}
          <br />
          Phishing feed: {statuses[report.feed_status]}
        </p>
        <p>
          Campaigns: {statuses[report.campaign_status]}
          {report.campaign_conflict
            ? " · conflicting legitimate feedback; match withheld"
            : report.campaign_match
              ? " · confirmed match"
              : ''}
          <br />
          DMARC aligned sender:{' '}
          {report.authenticated_sender ? 'Confirmed' : "Not confirmed"}
        </p>
      </div>
      {(
        [
          ['CRDF', report.crdf],
          ['VirusTotal', report.virustotal],
        ] as const
      ).map(([name, r]) => (
        <div key={name}>
          <p>
            <strong>{name}</strong> :{' '}
            {statuses[r.status] ?? "unrecorded status"} · {r.checked}{' '}
            indicators checked, {r.malicious} reported, {r.suspicious}{' '}
            suspicious, {r.unknown} unknown · {r.cache_hits} cached ·{' '}
            {r.elapsed_ms} ms
          </p>
          {r.failure && <p className="notice">{checkFailure(r.failure)}.</p>}
          {r.request_count!=null && <p className="muted small">{r.request_count} network requests · {Object.entries(r.http_status_counts ?? {}).map(([code,n])=>`HTTP ${code} : ${n}`).join(' · ') || "no recorded HTTP response"}{r.retry_after_seconds ? ` · pause requested: ${r.retry_after_seconds} s` : ''}</p>}
          {Object.entries(r.failure_counts ?? {}).map(([reason,n])=><p className="muted small" key={reason}>{checkFailure(reason)} : {n} incident(s), including those recovered.</p>)}
          {r.cache_hits > 0 && (
            <p className="muted small">
              {r.cache_hits} re-used cache result(s) without further consultation with the provider.
            </p>
          )}
          {!!r.omitted && (
            <p className="muted small">
              {r.omitted} indicators without usable results because of a deadline, quota or per-message limit.
            </p>
          )}
          {r.status === 'quota' && (
            <p className="muted small">
              Quota reached or pause imposed by the provider: some consultations have not been completed. This does not mean that the message is safe.
            </p>
          )}
          {[
            'unavailable',
            'busy',
            'limited',
            'stale',
            'not_run',
            'not_configured',
            'unknown',
          ].includes(r.status) && (
            <p className="muted small">
              This check has incomplete coverage or no usable result. That alone is not evidence of a threat.
            </p>
          )}
        </div>
      ))}
      <UrlResolutionDetails report={report.url_resolution} />
      {report.findings.length ? (
        <ul className="reasons">
          {report.findings.map((f, i) => (
            <li key={i}>
              <span>
                <code>{f.id}</code>
                <br />
                {f.detail}
                <small className="muted">
                  {' '}
                  ·{' '}
                  {f.sources
                    .map(
                      (s) =>
                        (
                          ({
                            headers: "Headers",
                            html: 'HTML',
                            text: "Text",
                            ocr_qr: 'OCR / QR',
                            crdf: 'CRDF',
                            virustotal: 'VirusTotal',
                            local_feedback: "Local corrections",
                            redirect: 'Redirection HTTP / HTML',
                            form: "Form (passive analysis)",
                          }) as Record<string, string>
                        )[s] || s,
                    )
                    .join(', ')}
                </small>
              </span>
              <code>
                {(
                  {
                    identity: "Identity",
                    link_structure: "Links",
                    link_reputation: "Reputation",
                    attachment: "Attachment",
                    campaign: "Campaign",
                  } as Record<string, string>
                )[f.family] || f.family}
              </code>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">
          No additional evidence from the checks carried out.
        </p>
      )}
    </section>
  );
}
