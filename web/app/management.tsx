'use client';
import { useState, useEffect } from 'react';
import { Plus, Trash2, FlaskConical, Download, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import type { CustomPolicy, Profile } from './custom-filtering';
export type RblList = {
  enabled: boolean;
  id: string;
  provider: string;
  zone: string;
  key_env: string | null;
  listed_codes: string[];
  observe_codes: string[];
  ipv6: boolean;
};
export type RblSettings = {
  action: 'observe' | 'defer' | 'reject';
  minimum_providers: number;
  timeout_ms: number;
  max_parallel: number;
  cache_entries: number;
  cache_ttl_seconds: number;
  lists: RblList[];
};
export type Detection = { modules: Record<string, Record<string, unknown>> };
export type Preference = {
  profile: Profile | null;
  rules: CustomPolicy['rules'];
};
export type Preferences = {
  enabled: boolean;
  minimum_threshold: number;
  maximum_threshold: number;
  max_rules: number;
  allowed_actions: ('deliver' | 'tag' | 'quarantine')[];
  mailboxes: Record<string, Preference>;
};
const labels: Record<string, string> = {
  authentication: "Authentication",
  bayes: "Bayes Statistics",
  campaign: "Campaigns",
  content: "Content",
  lexical: "Text",
  other: "Other signals",
  reputation: "Reputation",
  semantic: "Semantic analysis",
  smtp: "SMTP identity",
  protection: "CRDF, VirusTotal and link reputation",
  url_resolution: "Tracking URL redirects",
  max_urls: "URLs to follow by message",
  max_redirects: "Maximum redirects",
  blocked_ips: "IP addresses excluded from tracking",
  analysis: "Message Analysis",
  llm: "LLM analysis · Scaleway",
  vision: "Images, OCR and QR codes",
  smtp_policy: "SMTP and DNS identity",
  native: "Rust native rules",
  model: "Model",
  project_id: "Scaleway Project Identifier",
  monthly_budget_micro_eur: "Monthly budget (€)",
  input_micro_eur_per_million: "Input price (€ / million tokens)",
  output_micro_eur_per_million: "Output price (€ / million tokens)",
  pricing_checked_at: "Pricing verification date (UTC)",
  timeout_ms: "Maximum time (ms)",
  max_text_bytes: "Maximum text sent (bytes)",
  max_output_tokens: "Maximum response (tokens)",
  score_low: "Minimum score selected",
  score_high: "Maximum score selected",
  review_unconfirmed_high: "Also review high unconfirmed scores",
  max_parallel: "Simultaneous analyses",
  cache_entries: "cache entries",
  cache_ttl_seconds: "Maximum cache duration (seconds)",
  max_bytes: "Maximum size analysed (bytes)",
  max_parts: "Maximum parts analysed",
  max_part_bytes: "Maximum part size (bytes)",
  max_total_bytes: "Maximum total size (bytes)",
  max_pixels: "Maximum pixels",
  max_pages: "Maximum pages",
  max_text_chars: "Maximum recognized characters",
  max_codes: "Maximum decoded codes",
  fuzzy_memory: "Memory of similar campaigns",
  content_rules: "Content rules",
  patterns: "Text patterns",
  composites: "Combinations of signals",
  caps: "Ceilings per family",
  enabled: "Enabled",
  disabled: "Disabled rules",
  weights: "Custom weights",
  min: 'Minimum',
  max: 'Maximum',
  minimum_providers: "Independent providers required",
  minimum_threshold: 'Minimum personal threshold',
  maximum_threshold: 'Maximum personal threshold',
  max_rules: "Rules by address or domain",
  allowed_actions: "Allowed actions",
};
const limits: Record<string, [number, number]> = {
  min: [-5, 0],
  max: [0, 5],
  minimum_providers: [1, 8],
  minimum_threshold: [50, 100],
  maximum_threshold: [50, 100],
  max_rules: [0, 20],
  score_low: [0, 100],
  score_high: [0, 100],
};
export function JsonEditor({
  value,
  onChange,
  label,
}: {
  value: unknown;
  onChange: (v: unknown) => void;
  label: string;
}) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState('');
  return (
    <div className="json-setting">
      <label>
        {label}
        <textarea
          aria-label={label}
          rows={7}
          value={text ?? JSON.stringify(value, null, 2)}
          onChange={(e) => {
            setText(e.target.value);
            setError('');
          }}
        />
      </label>
      {text !== null && (
        <div className="management-toolbar">
          <span>Modified block. Validate it before saving the full configuration.</span>
          <Button
            variant="outline"
            onClick={() => {
              try {
                onChange(JSON.parse(text));
                setText(null);
                setError('');
              } catch (e) {
                setError(`Block refused: ${(e as Error).message}`);
              }
            }}
          >
            Validate this JSON block
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              setText(null);
              setError('');
            }}
          >
            Cancel Block
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </div>
  );
}
function Field({
  name,
  value,
  onChange,
}: {
  name: string;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const label = labels[name] ?? name;
  const euro = name.includes('micro_eur');
  if (typeof value === 'boolean')
    return (
      <label className="setting-toggle">
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span>{label}</span>
      </label>
    );
  if (typeof value === 'number' && name === 'pricing_checked_at')
    return (
      <label>
        {label}
        <input
          type="date"
          value={new Date(value * 1000).toISOString().slice(0, 10)}
          max={new Date().toISOString().slice(0, 10)}
          onChange={(e) => {
            if (e.target.value)
              onChange(
                Math.floor(
                  new Date(e.target.value + 'T00:00:00Z').getTime() / 1000,
                ),
              );
          }}
        />
      </label>
    );
  if (typeof value === 'number')
    return (
      <label>
        {label}
        <input
          type="number"
          step={euro ? '0.000001' : 'any'}
          min={limits[name]?.[0] ?? 0}
          max={limits[name]?.[1]}
          value={euro ? value / 1e6 : value}
          onChange={(e) => {
            if (
              e.target.value !== '' &&
              Number.isFinite(e.target.valueAsNumber)
            )
              onChange(
                euro
                  ? Math.round(e.target.valueAsNumber * 1e6)
                  : e.target.valueAsNumber,
              );
          }}
        />
      </label>
    );
  if (typeof value === 'string')
    return (
      <label>
        {label}
        <input value={value} onChange={(e) => onChange(e.target.value)} />
      </label>
    );
  if (value !== null && typeof value === 'object' && !Array.isArray(value))
    return (
      <fieldset className="advanced-setting">
        <legend>{label}</legend>
        <div className="management-grid">
          {Object.entries(value).map(([k, v]) => (
            <Field
              key={k}
              name={k}
              value={v}
              onChange={(next) => onChange({ ...value, [k]: next })}
            />
          ))}
        </div>
      </fieldset>
    );
  return (
    <details className="advanced-setting">
      <summary>{label} · Advanced adjustment</summary>
      <JsonEditor value={value} label={label} onChange={onChange} />
    </details>
  );
}
export type NativeRule = { id: string; label: string; weight: number };
function NativeRules({
  value,
  catalog,
  onChange,
}: {
  value: {
    enabled: boolean;
    disabled: string[];
    weights: Record<string, number>;
  };
  catalog: NativeRule[];
  onChange: (v: unknown) => void;
}) {
  return (
    <fieldset className="advanced-setting">
      <legend>HTML, MIME and attachments rules</legend>
      <label className="setting-toggle">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(e) => onChange({ ...value, enabled: e.target.checked })}
        />
        Enable Content Rules
      </label>
      <div className="management-grid">
        {catalog.map((r) => (
          <div key={r.id}>
            <label className="setting-toggle">
              <input
                type="checkbox"
                checked={!value.disabled.includes(r.id)}
                onChange={(e) =>
                  onChange({
                    ...value,
                    disabled: e.target.checked
                      ? value.disabled.filter((id) => id !== r.id)
                      : [...value.disabled, r.id],
                  })
                }
              />
              {r.label}
            </label>
            <label>
              Weight · {r.id}
              <input
                type="number"
                min={0}
                max={2}
                step="0.05"
                value={value.weights[r.id] ?? r.weight}
                onChange={(e) =>
                  onChange({
                    ...value,
                    weights: {
                      ...value.weights,
                      [r.id]: e.target.valueAsNumber,
                    },
                  })
                }
              />
            </label>
          </div>
        ))}
      </div>
      <Button
        variant="outline"
        onClick={() => onChange({ enabled: true, disabled: [], weights: {} })}
      >
        Restoring native rules
      </Button>
    </fieldset>
  );
}
export function DetectionSettings({
  value,
  onChange,
  nativeRules,
}: {
  value: Detection;
  nativeRules: NativeRule[];
  onChange: (v: Detection) => void;
}) {
  const [query, setQuery] = useState('');
  return (
    <div className="management-settings">
      <div className="panel-heading">
        <div>
          <h2>Engine parameters</h2>
          <p>
            Adjustments applied to new messages. Activation of each engine is set to &quot;detection engines&quot;.
          </p>
        </div>
      </div>
      <input
        aria-label="Find Parameter"
        placeholder="Search: budget, OCR, cache, delay..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <p className="notice">
        The LLM sends selected text to Scaleway. A 0–100 range selects all analysable messages. The budget, excerpt size and token prices determine the cost. An unavailable result is never evidence of spam.
      </p>
      {Object.entries(value.modules).map(([module, values]) => {
        const order = [
          'enabled',
          'model',
          'project_id',
          'monthly_budget_micro_eur',
          'max_text_bytes',
          'max_parallel',
          'timeout_ms',
          'score_low',
          'score_high',
          'review_unconfirmed_high',
          'max_output_tokens',
          'input_micro_eur_per_million',
          'output_micro_eur_per_million',
          'pricing_checked_at',
          'fuzzy_memory',
          'content_rules',
          'patterns',
          'composites',
          'caps',
        ];
        const entries = Object.entries(values)
          .sort(
            ([a], [b]) =>
              (order.indexOf(a) < 0 ? 100 : order.indexOf(a)) -
              (order.indexOf(b) < 0 ? 100 : order.indexOf(b)),
          )
          .filter(([k]) =>
            `${labels[module]} ${labels[k] ?? k}`
              .toLocaleLowerCase('en-GB')
              .includes(query.toLocaleLowerCase('en-GB')),
          );
        if (!entries.length) return null;
        return (
          <section key={module} className="management-card">
            <h3>{labels[module] ?? module}</h3>
            {module === 'native' && (
              <p>
                This engine remains in observation. The motifs associated with an adaptive model are protected by its validation.
              </p>
            )}
            <div className="management-grid">
              {entries.map(([name, v]) =>
                name === 'content_rules' ? (
                  <NativeRules
                    key={name}
                    catalog={nativeRules}
                    value={
                      v as {
                        enabled: boolean;
                        disabled: string[];
                        weights: Record<string, number>;
                      }
                    }
                    onChange={(next) =>
                      onChange({
                        modules: {
                          ...value.modules,
                          [module]: { ...values, [name]: next },
                        },
                      })
                    }
                  />
                ) : (
                  <Field
                    key={name}
                    name={name}
                    value={v}
                    onChange={(next) =>
                      onChange({
                        modules: {
                          ...value.modules,
                          [module]: { ...values, [name]: next },
                        },
                      })
                    }
                  />
                ),
              )}
            </div>
          </section>
        );
      })}
    </div>
  );
}
const presets = [
  { id: 'spamcop', provider: 'spamcop', zone: 'bl.spamcop.net' },
  { id: 'psbl', provider: 'psbl', zone: 'psbl.surriel.com' },
  { id: 'barracuda', provider: 'barracuda', zone: 'b.barracudacentral.org' },
];
export function RblEditor({
  value,
  onChange,
  csrf,
}: {
  value: RblSettings;
  onChange: (v: RblSettings) => void;
  csrf: string;
}) {
  const [ip, setIp] = useState('');
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  function update(i: number, patch: Partial<RblList>) {
    onChange({
      ...value,
      lists: value.lists.map((v, n) => (n === i ? { ...v, ...patch } : v)),
    });
    setResult(null);
  }
  function add(p: (typeof presets)[number]) {
    onChange({
      ...value,
      lists: [
        ...value.lists,
        {
          ...p,
          enabled: false,
          key_env: null,
          listed_codes: ['127.0.0.2'],
          observe_codes: [],
          ipv6: false,
        },
      ],
    });
  }
  return (
    <section className="management-settings">
      <h2>IP reputation · RBL</h2>
      <p>
        Checks run before DATA. Only configured return codes count as listings. DNS failures remain unavailable results. Zones operated by the same provider count once.
      </p>
      <div className="management-card">
        <div className="management-grid">
          <label>
            Action if providers agree
            <select
              value={value.action}
              onChange={(e) =>
                onChange({
                  ...value,
                  action: e.target.value as RblSettings['action'],
                })
              }
            >
              <option value="observe">Observe</option>
              <option value="defer">Defer · SMTP 451</option>
              <option value="reject">Reject · SMTP 550</option>
            </select>
          </label>
          {(
            [
              'minimum_providers',
              'timeout_ms',
              'max_parallel',
              'cache_entries',
              'cache_ttl_seconds',
            ] as const
          ).map((k) => (
            <Field
              key={k}
              name={k}
              value={value[k]}
              onChange={(v) => onChange({ ...value, [k]: v })}
            />
          ))}
        </div>
        <p>
          The Global Observation mode neutralizes refusals and postponements. The RBL control does not read the content of the messages.
        </p>
      </div>
      <div className="management-toolbar">
        {presets.map((p) => (
          <Button
            key={p.id}
            variant="outline"
            disabled={
              value.lists.length >= 7 ||
              value.lists.some((l) => l.zone === p.zone)
            }
            onClick={() => add(p)}
          >
            <Plus size={16} />
            {p.id}
          </Button>
        ))}
        <Button
          variant="outline"
          disabled={value.lists.length >= 7}
          onClick={() =>
            add({
              id: `liste-${Date.now().toString(36)}`,
              provider: 'personnalise',
              zone: '',
            })
          }
        >
          Add list
        </Button>
      </div>
      <p>
        New entries are disabled. Check the terms of the provider before activation; Barracuda requires registered access. Spamhaus DQS uses the dedicated connector. URIBL are not IP lists.
      </p>
      {value.lists.map((list, i) => (
        <section className="management-card" key={i}>
          <div className="management-toolbar">
            <label className="setting-toggle">
              <input
                type="checkbox"
                checked={list.enabled}
                onChange={(e) => update(i, { enabled: e.target.checked })}
              />
              <strong>{list.id || "New list"}</strong>
            </label>
            <Button
              aria-label={`Delete ${list.id}`}
              variant="ghost"
              onClick={() =>
                onChange({
                  ...value,
                  lists: value.lists.filter((_, n) => n !== i),
                })
              }
            >
              <Trash2 size={16} />
            </Button>
          </div>
          <div className="management-grid">
            {(['id', 'provider', 'zone'] as const).map((k) => (
              <label key={k}>
                {k === 'id'
                  ? "Username"
                  : k === 'provider'
                    ? "Independent provider"
                    : "DNS zone"}
                <input
                  value={list[k]}
                  onChange={(e) => update(i, { [k]: e.target.value })}
                />
              </label>
            ))}
            <label>
              Classification codes (separated by commas)
              <input
                value={list.listed_codes.join(', ')}
                onChange={(e) =>
                  update(i, {
                    listed_codes: e.target.value
                      .split(',')
                      .map((v) => v.trim()),
                  })
                }
              />
            </label>
            <label>
              Codes of policy to be observed
              <input
                value={list.observe_codes.join(', ')}
                onChange={(e) =>
                  update(i, {
                    observe_codes: e.target.value
                      ? e.target.value.split(',').map((v) => v.trim())
                      : [],
                  })
                }
              />
            </label>
            <label className="setting-toggle">
              <input
                type="checkbox"
                checked={list.ipv6}
                onChange={(e) => update(i, { ipv6: e.target.checked })}
              />
              Supported IPv6
            </label>
          </div>
          {list.key_env && (
            <small>Declared server key · protected destination</small>
          )}
        </section>
      ))}
      <section className="management-card">
        <h3>Test this draft</h3>
        <p>
          Query the active lists for this IP, without sending email or saving the settings.
        </p>
        <div className="management-toolbar">
          <input
            aria-label="Public IP to test"
            placeholder="Public IP address"
            value={ip}
            onChange={(e) => {
              setIp(e.target.value);
              setResult(null);
            }}
          />
          <Button
            disabled={busy || !ip}
            onClick={async () => {
              setBusy(true);
              setError('');
              setResult(null);
              try {
                setResult(
                  await api('/admin/rbl/test', { settings: value, ip }, csrf),
                );
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <FlaskConical size={16} />
            {busy ? "Test in progress..." : "Test"}
          </Button>
        </div>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {result !== null && (
          <pre className="management-result">
            {JSON.stringify(result, null, 2)}
          </pre>
        )}
      </section>
    </section>
  );
}
export function DelegationSettings({
  value,
  onChange,
}: {
  value: Preferences;
  onChange: (v: Preferences) => void;
}) {
  return (
    <section className="management-settings">
      <h2>Customization by users</h2>
      <p>
        The preferences belong to the address or domain. Each change requires an existing right of access. The rules of the administrator, the antivirus and the global mode remain priority.
      </p>
      <div className="management-grid">
        {(
          [
            'enabled',
            'minimum_threshold',
            'maximum_threshold',
            'max_rules',
          ] as const
        ).map((k) => (
          <Field
            key={k}
            name={k}
            value={value[k]}
            onChange={(v) => onChange({ ...value, [k]: v })}
          />
        ))}
      </div>
      <fieldset>
        <legend>Actions proposed to users</legend>
        {(['deliver', 'tag', 'quarantine'] as const).map((a) => (
          <label className="setting-toggle" key={a}>
            <input
              type="checkbox"
              checked={value.allowed_actions.includes(a)}
              onChange={(e) =>
                onChange({
                  ...value,
                  allowed_actions: e.target.checked
                    ? [...value.allowed_actions, a]
                    : value.allowed_actions.filter((v) => v !== a),
                })
              }
            />
            {a === 'deliver'
              ? "Deliver"
              : a === 'tag'
                ? "Tag"
                : "Quarantine"}
          </label>
        ))}
      </fieldset>
      <p>
        {Object.keys(value.mailboxes).length} Reducing permissions requires compatible existing preferences.
      </p>
      {Object.entries(value.mailboxes).map(([scope, p]) => (
        <details className="management-card" key={scope}>
          <summary>
            {scope} · {p.rules.length} rules
          </summary>
          <pre className="management-result">{JSON.stringify(p, null, 2)}</pre>
          <p>Edit this range from &quot;My Filters&quot;.</p>
          <Button
            variant="outline"
            onClick={() => {
              const mailboxes = { ...value.mailboxes };
              delete mailboxes[scope];
              onChange({ ...value, mailboxes });
            }}
          >
            Restore inheritance
          </Button>
        </details>
      ))}
    </section>
  );
}
export function ConfigurationTransfer({
  value,
  onChange,
  csrf,
}: {
  value: unknown;
  onChange: (v: unknown) => void;
  csrf: string;
}) {
  const [error, setError] = useState('');
  return (
    <section className="management-card">
      <h3>Export or import settings</h3>
      <p>
        Messaging configuration without secret keys. Import prepares a draft for review before application.
      </p>
      <div className="management-toolbar">
        <Button
          variant="outline"
          onClick={() => {
            const url = URL.createObjectURL(
              new Blob([JSON.stringify(value, null, 2)], {
                type: 'application/json',
              }),
            );
            const a = document.createElement('a');
            a.href = url;
            a.download = 'noisefence-configuration.json';
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          <Download size={16} />
          Export
        </Button>
        <label className="configuration-import">
          <Upload size={16} />
          Import JSON File
          <input
            type="file"
            accept="application/json,.json"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              try {
                if (file.size > 128 * 1024)
                  throw new Error("Maximum: 128 KiB.");
                const data = JSON.parse(await file.text());
                if (
                  !data ||
                  !Array.isArray(data.domains) ||
                  !Array.isArray(data.gateways) ||
                  !data.filters ||
                  !data.preferences ||
                  !data.detection ||
                  !data.rbl
                )
                  throw new Error("A recent NoiseFence configuration export is required.");
                const validated = await api<{ settings: unknown }>(
                  '/admin/config/validate',
                  { settings: data },
                  csrf,
                );
                onChange(validated.settings);
                setError('');
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          />
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </section>
  );
}

export function ManagedKeys({
  csrf,
  revision,
  onSaved,
}: {
  csrf: string;
  revision: number;
  onSaved: () => Promise<void>;
}) {
  const [keys, setKeys] = useState<Record<string, boolean>>({});
  const [provider, setProvider] = useState('spamhaus');
  const [key, setKey] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<Record<string, boolean>>('/admin/keys')
      .then(setKeys)
      .catch((e) => setError(e.message));
  }, [revision]);
  return (
    <section className="management-card management-settings">
      <h3>Spamhaus keys DQS and Scaleway</h3>
      <p>
        Server-side private storage. Keys are never rereaded in the browser, exported or saved in history. CRDF and VirusTotal are configured in &quot;Advanced Protection&quot;.
      </p>
      <div className="management-grid">
        <label>
          Provider
          <select
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setKey('');
              setNotice('');
            }}
          >
            <option value="spamhaus">
              Spamhaus DQS · {keys.spamhaus ? "configured" : "to be connected"}
            </option>
            {keys.scaleway_available && (
              <option value="scaleway">
                Scaleway · {keys.scaleway ? "configured" : "to be connected"}
              </option>
            )}
          </select>
        </label>
        <label>
          New key
          <input
            type="password"
            autoComplete="new-password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
      </div>
      <p>
        An authorized Spamhaus key is required. Save the key keeps the current connector activation; its switch is in the detection engines.
      </p>
      <Button
        disabled={busy || !key}
        onClick={async () => {
          setBusy(true);
          setError('');
          setNotice('');
          try {
            const result = await api<{ active: boolean; message?: string }>(
              '/admin/keys',
              { revision, provider, key },
              csrf,
            );
            setKey('');
            setNotice(
              result.active
                ? "Saved key. Reloaded configuration for future analyses."
                : (result.message ?? "Key saved."),
            );
            await onSaved();
          } catch (e) {
            setError((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Saving…" : "Save Key"}
      </Button>
      {notice && <output className="notice">{notice}</output>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </section>
  );
}
