'use client';
import { ProvidersOverview } from './providers-view';
import { SettingsHistory } from './settings-history-view';
import { SettingsComparison } from './settings-review-view';
import { DomainSetup } from './domain-setup-view';
import { LlmPricingNotice } from './llm-pricing-notice';
import { ResearchArchiveSettings, type ArchiveSettings } from './research-archive';
import { AdmissionEditor, type AdmissionSettings } from './smtp-admission';
import {
  RblEditor,
  DetectionSettings,
  DelegationSettings,
  ConfigurationTransfer,
  ManagedKeys,
  type RblSettings,
  type Detection,
  type Preferences,
} from './management';
import { CustomFiltering, type CustomPolicy } from './custom-filtering';
import { FilterSensitivity } from './filter-sensitivity-control';
import type { SensitivityLevel } from './filter-sensitivity';
import { Invitations } from './onboarding';
import { deliveryPolicy } from './policies';
import { SectionTabs, ConfirmDialog } from './console-ui';
import { matchesAccount } from './presentation';
import {
  ActionSettings,
  RuleSettings,
  type ActionPolicy,
  type Rule,
} from './actions';
import { MailingSettings, type MailingPolicy } from './mailing';
import { ProtectionSettings, type ProtectionPolicy } from './protection';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  Activity,
  Globe2,
  Network,
  SlidersHorizontal,
  Users,
  Server,
  Plus,
  ArrowUpRight,
  Save,
  RotateCcw,
  ShieldCheck,
  Trash2,
  CheckCircle2,
  Search,
  Mail,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import { ModelSources } from './model-sources';
import { ModelCatalog } from './model-catalog';
import { ActivationPanel, useActivation } from './activation-view';
import { saveNotice, savesBlocked, type SaveResult } from './activation';

export const navigation = [
  { id: 'messages', label: 'Messages', icon: Activity },
  { id: 'domains', label: "Domains", icon: Globe2 },
  { id: 'gateways', label: "Gateways", icon: Network },
  { id: 'cluster', label: "MX servers", icon: Server },
  { id: 'filters', label: "Filters", icon: SlidersHorizontal },
  { id: 'users', label: "Accounts & Access", icon: Users },
  { id: 'server', label: "Server status", icon: Server },
] as const;
export type Section = (typeof navigation)[number]['id'];
export type Gateway = { id: string; name: string; hosts: string[]; port: number };
type Domain = {
  name: string;
  gateway: string | null;
  enabled: boolean;
  accept_all_recipients: boolean;
  unknown_recipient_fallback?: string | null;
  recipient_verification?: { timeout_ms: number; positive_cache_seconds: number; negative_cache_seconds: number } | null;
  recipients: string[];
  aliases: Record<string, string>;
};
type Filters = {
  partial_actions?: boolean;
  resolve_uncertain_by_score?: boolean;
  mode: 'observe' | 'tag' | 'enforce';
  rule_weights: Record<string, number>;
  threshold: number;
  require_corroboration: boolean;
  authentication: boolean;
  antivirus: boolean;
  signatures: boolean;
  semantic: boolean;
  vision: boolean;
  llm: boolean;
  smtp_policy: boolean;
  smtp_policy_scoring: boolean;
  vision_scoring: boolean;
  reputation: boolean;
};
export type Settings = {
  quality_candidate?: {job:string|null;sha256:string|null}|null;
  research_archive?: ArchiveSettings | null;
  smtp_admission: AdmissionSettings;
  rbl: RblSettings;
  detection: Detection;
  preferences: Preferences;
  custom_filtering?: CustomPolicy | null;
  domains: Domain[];
  gateways: Gateway[];
  filters: Filters;
  actions: ActionPolicy | null;
  protection: ProtectionPolicy | null;
  mailing: MailingPolicy | null;
};
type Configuration = {
  native_rules: import('./management').NativeRule[];
  revision: number;
  actions: ActionPolicy;
  rules: Rule[];
  settings: Settings;
  available: Filters;
  threshold_locked: boolean;
  sensitivity_locked: boolean;
  sensitivity_levels: SensitivityLevel[];
  tag_ready: boolean;
  pub_tag_ready: boolean;
  mailing_available: boolean;
  hostname: string;
  version: string;
  max_connections: number;
  processing: number;
  relay_workers: number;
  max_message_bytes: number;
};
type Account = {
  username: string;
  admin: boolean;
  disabled: boolean;
  addresses: string[];
  version: number;
};
type Delivery = {
  node_id?: string | null;
  pending_command?: boolean;
  id: number;
  message_id: string;
  address: string;
  status: string;
  attempts: number;
  next_attempt: number;
  error: string | null;
  created: number;
};
type Metrics = {
  queued_deliveries: number;
  quarantined_deliveries: number;
  unnotified_failures: number;
  oldest_pending_age_seconds: number | null;
  received_last_hour: number;
  incomplete_last_hour: number;
  max_analysis_ms_last_hour: number;
  disk_available_bytes: number;
  llm_budget?: {
    pricing_checked_at?: number;
    accounted_micro_eur: number;
    monthly_budget_micro_eur: number;
    requests: number;
  };
};
const filterSections = [
  { id: 'providers', label: 'Providers & budgets', description: 'Loaded keys, quotas, costs, coverage and incidents', icon: <Activity size={19} /> },
  { id: 'models', label: 'Model files', description: 'Installed artifacts and explicit updates', icon: <Server size={19} /> },
  {
    id: 'admission',
    label: 'SMTP admission',
    description: "Greylisting, rate limits and delays",
    icon: <ShieldCheck size={19} />,
  },
  {
    id: 'rbl',
    label: "IP reputation · RBL",
    description: "DNS lists and SMTP responses",
    icon: <Globe2 size={19} />,
  },
  { id: 'research', label: 'R&D archive', description: 'Temporary encrypted originals and retention', icon: <Server size={19} /> },
  {
    id: 'parameters',
    label: "Advanced settings",
    description: "LLM, budgets, OCR and native rules",
    icon: <SlidersHorizontal size={19} />,
  },
  {
    id: 'delegation',
    label: "User preferences",
    description: "Rights, levels and personal actions",
    icon: <Users size={19} />,
  },
  {
    id: 'policy',
    label: "Policy & actions",
    description: "Levels, marking and quarantine",
    icon: <SlidersHorizontal size={19} />,
  },
  {
    id: 'detectors',
    label: "Detection engines",
    description: "Checks applied to each message",
    icon: <ShieldCheck size={19} />,
  },
  {
    id: 'rules',
    label: "Rule weights",
    description: "Adjust the contribution of signals",
    icon: <Activity size={19} />,
  },
  {
    id: 'custom',
    label: "Rules & profiles",
    description: "Exceptions by domain or address",
    icon: <Users size={19} />,
  },
  {
    id: 'protection',
    label: "Protection & reputation",
    description: "Links, identity and providers",
    icon: <Globe2 size={19} />,
  },
  {
    id: 'mailing',
    label: "Marketing & newsletters",
    description: "Recognize broadcast messages",
    icon: <Mail size={19} />,
  },
] as const;
type FilterSection = (typeof filterSections)[number]['id'];
const modules: {
  key: keyof Omit<
    Filters,
    'mode' | 'threshold' | 'require_corroboration' | 'rule_weights' | 'resolve_uncertain_by_score' | 'partial_actions'
  >;
  title: string;
  description: string;
}[] = [
  {
    key: 'authentication',
    title: "Authentication of e-mails",
    description: "SPF, DKIM, DMARC and ARC, verified prior to any change.",
  },
  {
    key: 'semantic',
    title: "Multilingual understanding",
    description:
      "Local model: combines message meaning and text clues.",
  },
  {
    key: 'antivirus',
    title: 'Antivirus',
    description: "Search for malicious files in attachments.",
  },
  {
    key: 'signatures',
    title: "Additional signatures",
    description: "Local detection of suspicious campaigns and content.",
  },
  {
    key: 'smtp_policy',
    title: "SMTP & DNS consistency",
    description:
      "Server identity, DNS reverse and sender consistency.",
  },
  {
    key: 'vision',
    title: "OCR, QR codes & barcodes",
    description:
      "Local text and code extraction from images and PDFs.",
  },
  {
    key: 'reputation',
    title: "Spamhaus DQS reputation",
    description:
      "Reputation of IPs and domains, with the key configured on the server.",
  },
  {
    key: 'llm',
    title: "Scaleway analysis",
    description:
      "External service for messages in the configured range, submitted to the monthly budget.",
  },
];
const stamp = (n: number) => new Date(n * 1000).toLocaleString("en-GB");
const lines = (s: string) =>
  s
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);
function normalize(s: Settings): Settings {
  return {
    ...s,
    protection: s.protection
      ? {
          ...s.protection,
          protected_names: s.protection.protected_names.map((x) => ({
            name: x.name.trim(),
            domain: x.domain.trim().toLowerCase(),
          })),
          reply_exceptions: s.protection.reply_exceptions
            .map((x) => x.trim().toLowerCase())
            .filter(Boolean),
          link_exceptions: s.protection.link_exceptions
            .map((x) => x.trim().toLowerCase())
            .filter(Boolean),
        }
      : null,
    gateways: s.gateways.map((g) => ({
      ...g,
      name: g.name.trim(),
      hosts: g.hosts.map((h) => h.trim().toLowerCase()).filter(Boolean),
    })),
    domains: s.domains.map((d) => ({
      ...d,
      name: d.name.trim().toLowerCase(),
      unknown_recipient_fallback: d.unknown_recipient_fallback?.trim() || undefined,
      recipients: d.recipients.map((a) => a.trim()).filter(Boolean),
    })),
  };
}
function ConfigCard({
  newItem,
  children,
}: {
  newItem: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(newItem);
  return (
    <details
      className="config-card"
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      {children}
    </details>
  );
}
function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled = false,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle-row ${disabled ? 'unavailable' : ''}`}>
      <span>
        <strong>{label}</strong>
        {description && <small>{description}</small>}
      </span>
      <input
        type="checkbox"
        role="switch"
        aria-checked={checked}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
    </label>
  );
}
function Aliases({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
}) {
  const [text, setText] = useState(
    value[''] ??
      Object.entries(value)
        .map(([a, b]) => `${a} = ${b}`)
        .join('\n'),
  );
  const [error, setError] = useState('');
  return (
    <label className="field">
      Explicit aliases{' '}
      <small>One alias per line: address@domain = destination@domain</small>
      <textarea
        value={text}
        rows={3}
        spellCheck={false}
        onChange={(e) => {
          const text = e.target.value;
          setText(text);
          const result: Record<string, string> = {};
          for (const line of lines(text)) {
            const i = line.indexOf(' = ');
            if (i < 1 || !line.slice(i + 3).trim()) {
              setError("Use the \"=\" separator surrounded by spaces.");
              onChange({ '': text });
              return;
            }
            const key = line.slice(0, i).trim();
            if (key in result) {
              setError("An alias is present several times.");
              onChange({ '': text });
              return;
            }
            result[key] = line.slice(i + 3).trim();
          }
          setError('');
          onChange(result);
        }}
      />
      {error && (
        <span role="alert" className="field-error">
          {error}
        </span>
      )}
    </label>
  );
}
export function AdminConsole({
  user,
  section,
  onDirty,
  onSetupDirty,
  onBusy,
  onApplied,
  onDomain,
}: {
  user: User;
  section: Section;
  onDirty: (v: boolean) => void;
  onSetupDirty: (v: boolean) => void;
  onBusy: (v: boolean) => void;
  onApplied: () => Promise<void>;
  onDomain: (name: string) => void;
}) {
  const activation = useActivation(user, true);
  const blocked = savesBlocked(activation.view, activation.error);
  const [modelChoice, setModelChoice] = useState<{digest:string;catalogId?:string;quality?:Settings['quality_candidate'];draft:string;revision:number} | null>(null);
  const [config, setConfig] = useState<Configuration | null>(null),
    [draft, setDraft] = useState<Settings | null>(null);
  const [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false),
    [reviewed, setReviewed] = useState<string | null>(null);
  const [refreshRequired, setRefreshRequired] = useState(false);
  const [lastSave, setLastSave] = useState<SaveResult | null>(null);
  const [discard, setDiscard] = useState(false);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const pageHeading = useRef<HTMLHeadingElement>(null);
  const receiptRef = useRef<HTMLOutputElement>(null);
  const alive = useRef(true);
  useEffect(() => {alive.current=true;return()=>{alive.current=false;};},[]);
  useEffect(() => {if(lastSave)receiptRef.current?.focus();},[lastSave]);
  const [accounts, setAccounts] = useState<Account[]>([]),
    [editing, setEditing] = useState<Account | null>(null),
    [password, setPassword] = useState('');
  const [operations, setOperations] = useState<{key:string;metrics:Metrics|null;deliveries:Delivery[]|null;metricsError:string;queueError:string}|null>(null);
  const [epoch, setEpoch] = useState(0);
  const [filterSection, setFilterSection] = useState<FilterSection>('policy');
  const [filterQuery, setFilterQuery] = useState('');
  const [setupOpen, setSetupOpen] = useState(false);
  const addDomainButton = useRef<HTMLButtonElement>(null);
  useEffect(() => { onSetupDirty(setupOpen); return () => onSetupDirty(false); }, [setupOpen, onSetupDirty]);
  useEffect(() => { onBusy(busy); return () => onBusy(false); }, [busy, onBusy]);
  function closeSetup() { setSetupOpen(false); requestAnimationFrame(() => addDomainButton.current?.focus()); }
  const [accountQuery, setAccountQuery] = useState('');
  const [accountFilter, setAccountFilter] = useState('all');
  const modelDraft = draft ? JSON.stringify(normalize(draft)) : '';
  const modelSelection = modelChoice?.draft === modelDraft && modelChoice?.revision === config?.revision ? modelChoice.digest : null;
  const catalogSelection = modelSelection ? modelChoice?.catalogId : undefined;
  const proposal = config && draft ? {
    revision: config.revision,
    settings: catalogSelection ? {...normalize(draft),quality_candidate:modelChoice?.quality ?? null} : normalize(draft),
    installation_models_sha256: catalogSelection ? null : modelSelection,
    catalog_models: catalogSelection ? {id:catalogSelection,sha256:modelSelection} : null,
  } : null;
  const reviewKey = JSON.stringify(proposal);
  const review = reviewed === reviewKey;
  const operationKey = JSON.stringify([user.username,section,epoch]);
  const operationView = operations?.key === operationKey ? operations : null;
  const metrics = operationView?.metrics ?? null;
  const deliveries = operationView?.deliveries ?? [];
  const dirty =
    !refreshRequired &&
    !!config &&
    !!draft &&
    (JSON.stringify(config.settings) !== JSON.stringify(draft) || modelSelection !== null);
  useEffect(() => {
    onDirty(dirty || setupOpen);
    const leave = (e: BeforeUnloadEvent) => {
      if (dirty || setupOpen) e.preventDefault();
    };
    window.addEventListener('beforeunload', leave);
    return () => window.removeEventListener('beforeunload', leave);
  }, [dirty, setupOpen, onDirty]);
  useEffect(() => {
    let active = true;
    api<Configuration>('/admin/config')
      .then((c) => {
        if (active) {
          setConfig(c);
          setDraft(c.settings);
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [user]);
  useEffect(() => {
    let active = true;
    if (section === 'users')
      api<Account[]>('/admin/users')
        .then((a) => {
          if (active) setAccounts(a);
        })
        .catch((e) => {
          if (active) setError(e.message);
        });
    const abort = new AbortController();
    if (section === 'server')
      void Promise.allSettled([
        api<Metrics>('/metrics',undefined,undefined,{signal:abort.signal,cache:'no-store'}),
        api<Delivery[]>('/admin/queue',undefined,undefined,{signal:abort.signal,cache:'no-store'}),
      ]).then(([m,d]) => {
        if(active)setOperations({key:operationKey,
          metrics:m.status==='fulfilled'?m.value:null,
          deliveries:d.status==='fulfilled'?d.value:null,
          metricsError:m.status==='rejected'?String(m.reason?.message??m.reason):'',
          queueError:d.status==='rejected'?String(d.reason?.message??d.reason):'',
        });
      });
    return () => {
      active = false;
      abort.abort();
    };
  }, [section, user, operationKey]);
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
    } catch (e) {
      if(alive.current)setError((e as Error).message);
    } finally {
      if(alive.current)setBusy(false);
    }
  }
  async function reload() {
    const c = await api<Configuration>('/admin/config',undefined,undefined,{cache:'no-store'});
    if(!alive.current)return;
    setConfig(c);
    setDraft(c.settings);
    setModelChoice(null);
    setReviewed(null);
    setRefreshRequired(false);
    setEpoch((e) => e + 1);
  }
  async function save() {
    if (!proposal || !review || blocked || refreshRequired) return;
    // The exact reviewed payload includes its revision and explicit model selection.
    let result: SaveResult;
    try {
      result = await api<SaveResult>('/admin/config', JSON.parse(reviewKey), user.csrf);
    } catch(e) {
      if(alive.current)setReviewed(null);
      throw e;
    }
    if(!alive.current)return;
    setLastSave(result);
    setReviewed(null);
    setRefreshRequired(true);
    try {
      await reload();
    } catch(e) {
      if(alive.current)setError(`Save acknowledged, but installed settings could not be refreshed. Refresh before editing again. ${(e as Error).message}`);
    }
    await activation.refresh();
    if(!alive.current)return;
    if(!result.staged) {
      try {await onApplied();}
      catch(e){if(alive.current)setError(`Settings were saved. The message overview could not be refreshed: ${(e as Error).message}`);}
    }
  }
  useEffect(() => {
    if (!config || dirty || busy || refreshRequired || !activation.view || activation.view.pending ||
        activation.view.installed_revision === config.revision) return;
    let active = true;
    api<Configuration>('/admin/config').then(c => {
      if (active) { setConfig(c); setDraft(c.settings); setReviewed(null); setNotice('Installed configuration refreshed.'); void onApplied().catch(e => setError(e.message)); }
    }).catch(e => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [activation.view, config, dirty, busy, refreshRequired, onApplied]);
  if (!config || !draft)
    return (
      <div className="panel">
        {error ? (
          <p role="alert" className="error">
            {error}
          </p>
        ) : (
          <p className="muted">Loading administration...</p>
        )}
      </div>
    );
  function domainAt(i: number, change: Partial<Domain>) {
    setDraft(
      (d) =>
        d && {
          ...d,
          domains: d.domains.map((v, j) => (i === j ? { ...v, ...change } : v)),
        },
    );
  }
  function gatewayAt(i: number, change: Partial<Gateway>) {
    setDraft(
      (d) =>
        d && {
          ...d,
          gateways: d.gateways.map((v, j) =>
            i === j ? { ...v, ...change } : v,
          ),
        },
    );
  }
  function filterAt<K extends keyof Filters>(key: K, value: Filters[K]) {
    setDraft((d) => d && { ...d, filters: { ...d.filters, [key]: value } });
  }
  return (
    <div className="admin-console">
      <ActivationPanel state={activation} user={user} administrator />
      <div className="page-heading">
        <div>
          <p className="eyebrow">
            {section === 'server' ? 'OPERATIONS' : 'ADMINISTRATION'}
          </p>
          <h1 ref={pageHeading} tabIndex={-1}>{navigation.find((n) => n.id === section)?.label}</h1>
          <p className="muted">
            {
              {
                domains:
                  "Domains that can receive messages on your gateway.",
                gateways:
                  "Destination servers, in order of priority.",
                filters:
                  "A common policy for consistent filtering across all your domains.",
                users:
                  "Manage access to individual addresses or entire domains.",
                server: "Delivery, capacity and history of change.",
                messages: '',
                cluster: "Configuration and supervision of MX servers.",
              }[section]
            }
          </p>
        </div>
        <span className="revision-badge">Revision {config.revision}</span>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && (
        <output className="notice">
          <CheckCircle2 size={17} />
          {notice}
        </output>
      )}
      {lastSave && <output ref={receiptRef} tabIndex={-1} className="notice">{saveNotice(lastSave)}</output>}
      {refreshRequired && <section className="panel" aria-label="Saved configuration refresh required"><p>Save acknowledged. Displayed settings may be stale; editing is disabled until they are refreshed.</p><Button disabled={busy} onClick={()=>void action(async()=>{await reload();await activation.refresh();setNotice('Installed settings refreshed.');requestAnimationFrame(()=>receiptRef.current?.focus());})}>Refresh installed settings</Button></section>}
      <fieldset className="admin-editors" disabled={busy || refreshRequired}>
      {section === 'domains' && (
        <>
          <div className="admin-summary">
            <span>
              <Globe2 size={19} />
              <strong>
                {draft.domains.filter((d) => d.enabled).length}
              </strong>{' '}
              {dirty ? "domains enabled in draft" : "active domains"}
            </span>
            <span>
              <Network size={19} />
              <strong>{draft.gateways.length}</strong> Available gateways
            </span>
            <Button ref={addDomainButton} disabled={setupOpen} onClick={() => setSetupOpen(true)}>
              <Plus size={16} /> Add domain
            </Button>
          </div>
          {setupOpen && <DomainSetup settings={normalize(draft)} revision={config.revision} hostname={config.hostname} user={user}
            onClose={closeSetup} onPrepared={next => { setDraft(next); setReviewed(null); closeSetup(); setNotice('Domain added to the draft. Review all changes before applying.'); }} />}
          <div className="notice">
            To receive emails, the domain must also be configured at your email host. After validation of the delivery, its DNS will point to {config.hostname}.
          </div>
          <div className="admin-cards">
            {draft.domains.map((d, i) => (
              <ConfigCard key={`${epoch}-${i}`} newItem={!d.name}>
                <summary>
                  <span className="card-icon">
                    <Globe2 size={21} />
                  </span>
                  <span className="card-title">
                    <strong>{d.name || "New domain"}</strong>
                    <small>
                      {d.accept_all_recipients
                        ? "All accepted addresses"
                        : `${d.recipients.length} explicit address(es)`}{' '}
                      · {Object.keys(d.aliases).length} alias
                    </small>
                  </span>
                  <span className={`status ${d.enabled ? 'good' : ''}`}>
                    {d.enabled ? "Enabled" : "Disabled"}
                  </span>
                </summary>
                <div className="card-body">
                  <div className="form-grid">
                    <label className="field" htmlFor={`domain-name-${i}`}>
                      Domain name
                      <Input
                        id={`domain-name-${i}`}
                        value={d.name}
                        placeholder="example.test"
                        onChange={(e) => domainAt(i, { name: e.target.value })}
                        spellCheck={false}
                      />
                    </label>
                    <label className="field">
                      Delivery gateway
                      <select
                        value={d.gateway ?? ''}
                        onChange={(e) =>
                          domainAt(i, { gateway: e.target.value || null })
                        }
                      >
                        <option value="">Alias only</option>
                        {draft.gateways.map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name || "New gateway"}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <Toggle
                    label="Reception enabled"
                    description="A disabled domain refuses new SMTP recipients."
                    checked={d.enabled}
                    onChange={(enabled) => domainAt(i, { enabled })}
                  />
                  <Toggle
                    label="Accept all domain addresses"
                    description={`No individual mailbox declarations: *@${d.name || 'example.test'}. The final destination must accept these addresses.`}
                    checked={d.accept_all_recipients}
                    onChange={(accept_all_recipients) =>
                      domainAt(i, { accept_all_recipients })
                    }
                  />
                  <Toggle
                    label="Verify recipients at destination"
                    description="Check the canonical mailbox over verified TLS before accepting mail. Unknown addresses receive 550; unavailable checks receive 451 for retry. Upgrade every MX before enabling. Explicit aliases use their destination domain's policy."
                    checked={!!d.recipient_verification}
                    onChange={(enabled) => domainAt(i, {
                      recipient_verification: enabled ? { timeout_ms: 8000, positive_cache_seconds: 60, negative_cache_seconds: 30 } : undefined,
                      ...(enabled ? { unknown_recipient_fallback: undefined } : {}),
                    })}
                  />
                  {d.recipient_verification && <div className="form-grid">
                    {([
                      ['timeout_ms', 'Verification deadline (ms)', 100, 15000],
                      ['positive_cache_seconds', 'Accepted recipient cache (seconds)', 0, 300],
                      ['negative_cache_seconds', 'Unknown recipient cache (seconds)', 0, 60],
                    ] as const).map(([key, label, min, max]) => <label className="field" key={key}>
                      {label}
                      <Input type="number" min={min} max={max} value={d.recipient_verification![key]}
                        onChange={(e) => domainAt(i, { recipient_verification: { ...d.recipient_verification!, [key]: Number(e.target.value) } })} />
                    </label>)}
                  </div>}
                  <label className="field" htmlFor={`domain-fallback-${i}`}>
                    Unknown-recipient fallback
                    <Input id={`domain-fallback-${i}`} value={d.unknown_recipient_fallback ?? ''}
                      placeholder={`postmaster@${d.name || 'example.test'}`}
                      disabled={!!d.recipient_verification}
                      onChange={(e) => domainAt(i, { unknown_recipient_fallback: e.target.value || null })}
                      spellCheck={false} />
                    <small>Optional mailbox in this domain. Used only after an upstream 550 5.1.1 recipient refusal. Existing recipients, spam refusals and temporary failures keep their normal handling. All MX nodes must support this setting. Incompatible with destination recipient verification.</small>
                  </label>
                  {!d.accept_all_recipients && (
                    <label className="field">
                      Authorized addresses
                      <small>One full address per line.</small>
                      <textarea
                        value={d.recipients.join('\n')}
                        rows={3}
                        onChange={(e) =>
                          domainAt(i, {
                            recipients: e.target.value.split('\n'),
                          })
                        }
                      />
                    </label>
                  )}
                  <Aliases
                    key={`${epoch}-${i}`}
                    value={d.aliases}
                    onChange={(aliases) => domainAt(i, { aliases })}
                  />
                  <div className="card-actions">
                    <Button
                      variant="outline"
                      disabled={
                        !config.settings.domains.some(
                          (old) => old.name === d.name,
                        )
                      }
                      onClick={() => onDomain(d.name)}
                    >
                      View Messages
                      <ArrowUpRight size={15} />
                    </Button>
                    <Button
                      variant="ghost"
                      className="danger"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Remove ${d.name || "this area"} ? Messages already accepted will continue to be delivered.`,
                          )
                        ) {
                          setDraft({
                            ...draft,
                            domains: draft.domains.filter((_, j) => i !== j),
                          });
                          setEpoch((e) => e + 1);
                        }
                      }}
                    >
                      <Trash2 size={15} />
                      Remove
                    </Button>
                  </div>
                </div>
              </ConfigCard>
            ))}
          </div>
        </>
      )}
      {section === 'gateways' && (
        <>
          <div className="admin-summary">
            <span>
              <ShieldCheck size={19} />
              TLS checked to public servers
            </span>
            <Button
              onClick={() =>
                setDraft({
                  ...draft,
                  gateways: [
                    ...draft.gateways,
                    {
                      id: crypto.randomUUID(),
                      name: '',
                      hosts: [''],
                      port: 25,
                    },
                  ],
                })
              }
            >
              <Plus size={16} />
              Add Gateway
            </Button>
          </div>
          <div className="admin-cards">
            {draft.gateways.map((g, i) => (
              <ConfigCard key={`${epoch}-${g.id}`} newItem={!g.name}>
                <summary>
                  <span className="card-icon">
                    <Network size={21} />
                  </span>
                  <span className="card-title">
                    <strong>{g.name || "New gateway"}</strong>
                    <small>
                      {g.hosts.filter(Boolean).join(' → ') ||
                        "Destination required"}
                    </small>
                  </span>
                  <span className="status">Port {g.port}</span>
                </summary>
                <div className="card-body">
                  <div className="form-grid">
                    <label className="field" htmlFor={`gateway-name-${i}`}>
                      Gateway name
                      <Input
                        id={`gateway-name-${i}`}
                        value={g.name}
                        onChange={(e) => gatewayAt(i, { name: e.target.value })}
                        placeholder="Proton Mail"
                      />
                    </label>
                    <label className="field" htmlFor={`gateway-port-${i}`}>
                      SMTP port
                      <Input
                        id={`gateway-port-${i}`}
                        type="number"
                        min={1}
                        max={65535}
                        value={g.port}
                        onChange={(e) =>
                          gatewayAt(i, { port: Number(e.target.value) })
                        }
                      />
                    </label>
                  </div>
                  <label className="field">
                    Reception servers
                    <small>
                      One DNS name per line. First priority server, then backup servers. A suffix:port can replace the common port.
                    </small>
                    <textarea
                      value={g.hosts.join('\n')}
                      onChange={(e) =>
                        gatewayAt(i, { hosts: e.target.value.split('\n') })
                      }
                      rows={3}
                      spellCheck={false}
                      placeholder={'mail.protonmail.ch\nmailsec.protonmail.ch'}
                    />
                  </label>
                  <p className="small muted">
                    Associated domains:{' '}
                    {draft.domains
                      .filter((d) => d.gateway === g.id)
                      .map((d) => d.name)
                      .join(', ') || "None"}
                    . New routes apply to future messages; already queued deliveries retain their destination.
                  </p>
                  <div className="card-actions">
                    <span className="small muted">
                      Mandatory certificate encryption and verification
                    </span>
                    <Button
                      variant="ghost"
                      className="danger"
                      disabled={draft.domains.some((d) => d.gateway === g.id)}
                      onClick={() => {
                        if (
                          window.confirm(
                            "Remove this unused gateway?",
                          )
                        )
                          setDraft({
                            ...draft,
                            gateways: draft.gateways.filter(
                              (x) => x.id !== g.id,
                            ),
                          });
                      }}
                    >
                      <Trash2 size={15} />
                      Remove
                    </Button>
                  </div>
                </div>
              </ConfigCard>
            ))}
          </div>
        </>
      )}
      {section === 'filters' && (
        <>
          <section className="filter-guide" aria-label="Filtering overview">
            <div><span className="eyebrow">ONE POLICY, CLEAR OUTCOMES</span><h2>Control how mail is assessed and delivered</h2><p>Set the organization policy, then refine it for domains and recipients. The risk index, classification and delivery action remain separate.</p></div>
            <div className="filter-guide-state"><span className="small">{!activation.view || activation.error ? 'Installed policy · readiness unavailable' : activation.view.smtp_ready ? 'Installed policy' : 'Installed policy · SMTP paused'}</span><strong>{config.settings.filters.mode === 'observe' ? 'Observation' : 'Actions enabled'}</strong><span>{config.settings.filters.mode === 'observe' ? 'Decisions recorded · mail delivered unchanged' : 'Configured actions apply to new mail'}</span></div>
          </section>
          <div className="policy-summary">
            <span>
              <strong>
                {draft.filters.mode === 'observe'
                  ? 'Observation'
                  : "Actions enabled"}
              </strong>
              <small>Draft mode</small>
            </span>
            <span>
              <strong>
                {modules.filter((m) => draft.filters[m.key]).length} /{' '}
                {modules.length}
              </strong>
              <small>Optional checks enabled</small>
            </span>
            <span>
              <strong>
                {Object.keys(draft.filters.rule_weights ?? {}).length}
              </strong>
              <small>Custom weights</small>
            </span>
            <span className={`status ${dirty ? 'review' : 'good'}`}>
              {dirty
                ? "Unsaved changes"
                : activation.view?.pending ? "Activation pending" : "Installed configuration"}
            </span>
          </div>
          <label className="filter-search"><Search size={18} aria-hidden="true"/><span className="sr-only">Find a filter setting</span><Input type="search" placeholder="Find settings: RBL, quarantine, LLM, OCR, budgets…" value={filterQuery} onChange={e => setFilterQuery(e.target.value)}/>{filterQuery && <button type="button" onClick={() => setFilterQuery('')} aria-label="Clear settings search">Clear</button>}</label>
          {filterQuery && <output className="small muted">Select a matching section below. Your current draft is preserved.</output>}
          <SectionTabs
            id="filters"
            label="Filter headings"
            presentation="cards"
            items={filterSections}
            query={filterQuery}
            value={filterSection}
            onChange={setFilterSection}
          />
          <div id="filters-panel-providers" role="tabpanel" aria-labelledby="filters-tab-providers" hidden={filterSection !== 'providers'} className="filter-section">
            {section === 'filters' && filterSection === 'providers' && <ProvidersOverview revision={config.revision} hasDraft={dirty} onSettings={target => {setFilterQuery(''); setFilterSection(target); requestAnimationFrame(() => document.getElementById(`filters-tab-${target}`)?.focus());}}/>}
          </div>
          <div
            id="filters-panel-admission"
            role="tabpanel"
            aria-labelledby="filters-tab-admission"
            hidden={filterSection !== 'admission'}
            className="filter-section"
          >
            {draft.smtp_admission && (
              <AdmissionEditor
                value={draft.smtp_admission}
                onChange={(smtp_admission) =>
                  setDraft({ ...draft, smtp_admission })
                }
              />
            )}
          </div>
          <div
            id="filters-panel-rbl"
            role="tabpanel"
            aria-labelledby="filters-tab-rbl"
            hidden={filterSection !== 'rbl'}
            className="filter-section"
          >
            <RblEditor
              value={draft.rbl}
              onChange={(rbl) => setDraft({ ...draft, rbl })}
              csrf={user.csrf}
            />
          </div>
          <div id="filters-panel-research" role="tabpanel" aria-labelledby="filters-tab-research" hidden={filterSection !== 'research'} className="filter-section">
            <ResearchArchiveSettings value={draft.research_archive ?? null} onChange={research_archive => setDraft({...draft,research_archive})} domains={draft.domains.filter(d => d.enabled).map(d => d.name)} />
          </div>
          <div
            id="filters-panel-parameters"
            role="tabpanel"
            aria-labelledby="filters-tab-parameters"
            hidden={filterSection !== 'parameters'}
            className="filter-section"
          >
            <DetectionSettings
              nativeRules={config.native_rules}
              value={draft.detection}
              onChange={(detection) => setDraft({ ...draft, detection })}
            />
            <ManagedKeys
              csrf={user.csrf}
              revision={config.revision}
              onSaved={async () => {
                const fresh = await api<Configuration>('/admin/config');
                setConfig(fresh);
                setEpoch((v) => v + 1);
              }}
            />
            <ConfigurationTransfer
              csrf={user.csrf}
              value={draft}
              onChange={(v) => setDraft(v as Settings)}
            />
          </div>
          <div
            id="filters-panel-delegation"
            role="tabpanel"
            aria-labelledby="filters-tab-delegation"
            hidden={filterSection !== 'delegation'}
            className="filter-section"
          >
            <DelegationSettings
              value={draft.preferences}
              onChange={(preferences) => setDraft({ ...draft, preferences })}
            />
          </div>
          <div
            id="filters-panel-custom"
            role="tabpanel"
            aria-labelledby="filters-tab-custom"
            hidden={filterSection !== 'custom'}
            className="filter-section"
          >
            <CustomFiltering
              policy={draft.custom_filtering}
              savedPolicy={config.settings.custom_filtering ?? null}
              onChange={(custom_filtering) =>
                setDraft({ ...draft, custom_filtering })
              }
              domains={draft.domains
                .filter((d) => d.enabled)
                .map((d) => d.name)}
              locked={config.sensitivity_locked}
              levels={config.sensitivity_levels}
              csrf={user.csrf}
            />
          </div>
          <div id="filters-panel-models" role="tabpanel" aria-labelledby="filters-tab-models" hidden={filterSection !== 'models'} className="filter-section">
            <ModelSources revision={config.revision} settings={normalize(draft)} csrf={user.csrf} disabled={busy || blocked || setupOpen} coordinated={!!activation.view?.coordinated} selected={catalogSelection ? null : modelSelection} onSelect={digest => setModelChoice(digest ? {digest,draft:modelDraft,revision:config.revision} : null)} />
            <ModelCatalog revision={config.revision} settings={normalize(draft)} csrf={user.csrf} disabled={busy || blocked || setupOpen} coordinated={!!activation.view?.coordinated} selected={catalogSelection ?? null} onSelect={choice => {
              if (!choice) {setModelChoice(null);return;}
              setModelChoice({digest:choice.digest,catalogId:choice.id,quality:choice.quality_candidate,draft:modelDraft,revision:config.revision});
            }} />
          </div>
          <div
            id="filters-panel-policy"
            role="tabpanel"
            aria-labelledby="filters-tab-policy"
            hidden={filterSection !== 'policy'}
            className="filter-section"
          >
            <FilterSensitivity
              policy={draft.custom_filtering}
              onChange={(custom_filtering) =>
                setDraft({ ...draft, custom_filtering })
              }
              domains={draft.domains
                .filter((d) => d.enabled)
                .map((d) => d.name)}
              actions={deliveryPolicy(draft)}
              levels={config.sensitivity_levels}
              locked={config.sensitivity_locked}
              modelThreshold={draft.filters.threshold}
            />
            <div className="panel filter-policy">
              <div>
                <h2>Filter behaviour</h2>
                <p className="muted small">
                  The observation analyses and transmits without prefixes. The active mode applies the actions chosen for the new messages: transmission, marking or quarantine.
                </p>
              </div>
              <div className="form-grid">
                <label className="field">
                  Operating mode
                  <select
                    value={draft.filters.mode}
                    onChange={(e) =>
                      filterAt('mode', e.target.value as Filters['mode'])
                    }
                  >
                    <option value="observe">
                      Observation — analyse and transmit
                    </option>
                    {draft.filters.mode === 'tag' && (
                      <option value="tag">
                        Active — Existing marking configuration
                      </option>
                    )}
                    <option value="enforce">
                      Active — apply delivery actions
                    </option>
                  </select>
                </label>
                <label className="field" htmlFor="filter-threshold">
                  Content reference threshold / 100
                  <Input
                    id="filter-threshold"
                    type="number"
                    min={0}
                    max={100}
                    step={0.1}
                    value={draft.filters.threshold}
                    disabled={config.threshold_locked}
                    onChange={(e) =>
                      filterAt('threshold', Number(e.target.value))
                    }
                  />
                  <small>
                    {config.threshold_locked
                      ? "Threshold related to the calibration of the multilingual model. A new calibration is required to modify it."
                      : "A higher threshold reduces the number of messages marked."}
                  </small>
                </label>
              </div>
              <p className="notice">Automatic decisions are always enabled. Inconclusive detector results use the configured threshold, subject to the corroboration requirement. Messages without a usable score are accepted with an analysis-unavailable notice. Coverage and action restrictions remain visible separately.</p>
              <Toggle
                label="Apply actions when decision-specific evidence is sufficient"
                description="Allow actions on partial analyses only when the selected decision has its required evidence. Score-based spam needs readable content, automatic score resolution and the applicable threshold. Explicit matched rules remain separate. Tagging still requires a ready ARC renderer and Proton validation. Off by default; qualify the policy and upgrade every MX before activation."
                checked={Boolean(draft.filters.partial_actions)}
                onChange={(v) => filterAt('partial_actions', v)}
              />
              <Toggle
                label="Require corroboration before classifying spam"
                description="When enabled, a high legacy content index without corroborating evidence is accepted as Ham. The score cannot confirm itself. Malware retains priority; Rspamd never supplies corroboration."
                checked={Boolean(draft.filters.require_corroboration)}
                onChange={(v) => filterAt('require_corroboration', v)}
              />
              {!config.tag_ready && (
                <p className="notice">
                  Marking requires validation of Proton delivery and ARC configuration. The server will refuse activation until these conditions are met.
                </p>
              )}
            </div>
            <ActionSettings
              policy={deliveryPolicy(draft)}
              mode={draft.filters.mode}
              partialActions={Boolean(draft.filters.partial_actions)}
              spamTagReady={config.tag_ready}
              pubTagReady={config.pub_tag_ready}
              publicityEnabled={!!draft.mailing}
              onChange={(actions) => setDraft({ ...draft, actions })}
            />
          </div>
          <div
            id="filters-panel-detectors"
            role="tabpanel"
            aria-labelledby="filters-tab-detectors"
            hidden={filterSection !== 'detectors'}
            className="filter-section"
          >
            <div className="module-grid">
              {modules.map((m) => (
                <section className="module-card" key={m.key}>
                  <Toggle
                    label={m.title}
                    description={m.description}
                    checked={Boolean(draft.filters[m.key])}
                    disabled={
                      m.key !== 'authentication' && !config.available[m.key]
                    }
                    onChange={(v) => filterAt(m.key, v)}
                  />
                  <span
                    className={`status ${draft.filters[m.key] ? 'good' : ''}`}
                  >
                    {m.key !== 'authentication' && !config.available[m.key]
                      ? "To be configured on the server"
                      : draft.filters[m.key]
                        ? "Enabled"
                        : "Disabled"}
                  </span>
                </section>
              ))}
            </div>
            <section className="panel">
              <h2>Contribution to the score</h2>
              <p className="muted small">
                Observation records these signals. Enabling their contribution changes future scores and requires a quality evaluation.
              </p>
              <Toggle
                label="Include SMTP and DNS signals in the score"
                checked={draft.filters.smtp_policy_scoring}
                disabled={!draft.filters.smtp_policy}
                onChange={(v) => filterAt('smtp_policy_scoring', v)}
              />
              <Toggle
                label="OCR text and decoded links in score"
                checked={draft.filters.vision_scoring}
                disabled={!draft.filters.vision}
                onChange={(v) => filterAt('vision_scoring', v)}
              />
            </section>
          </div>
          <div
            id="filters-panel-rules"
            role="tabpanel"
            aria-labelledby="filters-tab-rules"
            hidden={filterSection !== 'rules'}
            className="filter-section"
          >
            <RuleSettings
              rules={config.rules}
              weights={draft.filters.rule_weights ?? {}}
              onChange={(rule_weights) =>
                setDraft({
                  ...draft,
                  filters: { ...draft.filters, rule_weights },
                })
              }
            />
          </div>
          <div
            id="filters-panel-protection"
            role="tabpanel"
            aria-labelledby="filters-tab-protection"
            hidden={filterSection !== 'protection'}
            className="filter-section"
          >
            <ProtectionSettings
              key={`${user.username}:${config.revision}:${epoch}`}
              revision={config.revision}
              policy={draft.protection}
              user={user}
              onChange={(protection) => setDraft({ ...draft, protection })}
            />
          </div>
          <div
            id="filters-panel-mailing"
            role="tabpanel"
            aria-labelledby="filters-tab-mailing"
            hidden={filterSection !== 'mailing'}
            className="filter-section"
          >
            <MailingSettings
              actionsManaged
              policy={draft.mailing}
              available={config.mailing_available}
              tagReady={config.pub_tag_ready}
              mode={draft.filters.mode}
              onChange={(mailing) => setDraft({ ...draft, mailing })}
            />
          </div>
        </>
      )}
      {section === 'users' && (
        <>
          <Invitations user={user} />
          <div className="admin-summary">
            <span>
              <Users size={19} />
              <strong>{accounts.length}</strong> accounts ·{' '}
              {accounts.filter((a) => a.admin && !a.disabled).length}{' '}
              active administrator(s)
            </span>
            <Button
              onClick={() => {
                setEditing({
                  username: '',
                  admin: false,
                  disabled: false,
                  addresses: [],
                  version: -1,
                });
                setPassword('');
              }}
            >
              <Plus size={16} />
              Create an account
            </Button>
          </div>
          <div className="directory-toolbar">
            <label className="search" htmlFor="account-search">
              <Search size={17} />
              <Input
                id="account-search"
                aria-label="Search for an account or access"
                placeholder="Search for an account or address..."
                value={accountQuery}
                onChange={(e) => setAccountQuery(e.target.value)}
                maxLength={150}
              />
            </label>
            <label className="directory-filter">
              Show
              <select
                aria-label="Filter accounts"
                value={accountFilter}
                onChange={(e) => setAccountFilter(e.target.value)}
              >
                <option value="all">All accounts</option>
                <option value="admin">Administrators</option>
                <option value="user">Users</option>
                <option value="disabled">Disabled accounts</option>
              </select>
            </label>
          </div>
          {editing && (
            <form
              className="panel account-editor"
              onSubmit={(e) => {
                e.preventDefault();
                void action(async () => {
                  await api(
                    '/admin/users',
                    {
                      ...editing,
                      addresses: editing.addresses
                        .map((a) => a.trim())
                        .filter(Boolean),
                      password: password || null,
                    },
                    user.csrf,
                  );
                  const self = editing.username === user.username;
                  setEditing(null);
                  setPassword('');
                  setEpoch((e) => e + 1);
                  setNotice(
                    "Registered account. Previous sessions of this account have been revoked.",
                  );
                  if (self) window.dispatchEvent(new Event('session-expired'));
                });
              }}
            >
              <h2>
                {editing.version < 0
                  ? "Create an account"
                  : `Edit ${editing.username}`}
              </h2>
              <div className="form-grid">
                <label className="field" htmlFor="account-name">
                  Username
                  <Input
                    id="account-name"
                    required
                    autoComplete="off"
                    value={editing.username}
                    disabled={editing.version >= 0}
                    maxLength={100}
                    onChange={(e) =>
                      setEditing({ ...editing, username: e.target.value })
                    }
                  />
                </label>
                <label className="field" htmlFor="account-password">
                  {editing.version < 0
                    ? "Password"
                    : "New password (optional)"}
                  <Input
                    id="account-password"
                    type="password"
                    autoComplete="new-password"
                    required={editing.version < 0}
                    minLength={12}
                    maxLength={128}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
              </div>
              <Toggle
                label="Organization administrator"
                description="Can modify the configuration and view all messages from all domains."
                checked={editing.admin}
                onChange={(admin) => setEditing({ ...editing, admin })}
              />
              {!editing.admin && (
                <label className="field">
                  Authorized addresses and domains
                  <small>
                    One address per line; use *@example.test to give access to an entire already registered domain.
                  </small>
                  <textarea
                    rows={4}
                    value={editing.addresses.join('\n')}
                    onChange={(e) =>
                      setEditing({
                        ...editing,
                        addresses: e.target.value.split('\n'),
                      })
                    }
                    placeholder={"alice@example.fr *@other-domain.fr"}
                  />
                </label>
              )}
              <Toggle
                label="Account disabled"
                description="Sign-in is blocked and existing sessions are revoked when saved."
                checked={editing.disabled}
                onChange={(disabled) => setEditing({ ...editing, disabled })}
              />
              <div className="card-actions">
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => {
                    setEditing(null);
                    setPassword('');
                  }}
                >
                  Cancel
                </Button>
                <Button disabled={busy} type="submit">
                  Save account
                </Button>
              </div>
            </form>
          )}
          <div className="panel table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Role</th>
                  <th>Access</th>
                  <th>State</th>
                  <th>
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {accounts
                  .filter((a) => matchesAccount(a, accountQuery, accountFilter))
                  .map((a) => (
                    <tr key={a.username}>
                      <td>
                        <strong>{a.username}</strong>
                        {a.username === user.username && (
                          <small className="muted"> · You</small>
                        )}
                      </td>
                      <td>{a.admin ? "Administrator" : "User"}</td>
                      <td className="wrap">
                        {a.admin
                          ? "All domains"
                          : a.addresses.join(', ') || "No access"}
                      </td>
                      <td>
                        <span className={`status ${a.disabled ? '' : 'good'}`}>
                          {a.disabled ? "Disabled" : "Enabled"}
                        </span>
                      </td>
                      <td>
                        <Button
                          variant="ghost"
                          onClick={() => {
                            setEditing({ ...a });
                            setPassword('');
                          }}
                        >
                          Edit
                        </Button>
                      </td>
                    </tr>
                  ))}
                {!accounts.some((a) =>
                  matchesAccount(a, accountQuery, accountFilter),
                ) && (
                  <tr>
                    <td colSpan={5} aria-label="No matching account">
                      <div className="empty compact">
                        <h2>No matching account</h2>
                        <p>Change the search or access criteria.</p>
                        <Button
                          variant="outline"
                          onClick={() => {
                            setAccountQuery('');
                            setAccountFilter('all');
                          }}
                        >
                          Reset criteria
                        </Button>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
      {section === 'server' && (
        <>
          <div className="admin-summary">
            <span>
              <Server size={19} />
              {config.hostname}
              <span className="status">v{config.version}</span>
            </span>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setEpoch((e) => e + 1)}
            >
              Refresh
            </Button>
          </div>
          {operationView?.metricsError && <p role="alert" className="error">{operationView.metricsError} Metrics are unavailable.</p>}
          <div className="stats">
            <section>
              <span>Messages · last hour</span>
              <strong>{metrics?.received_last_hour ?? '—'}</strong>
              <small className="muted">
                {metrics?.incomplete_last_hour ?? '—'} incomplete analyses
              </small>
            </section>
            <section>
              <span>Pending deliveries</span>
              <strong>{metrics?.queued_deliveries ?? '—'}</strong>
              <small className="muted">
                {metrics?.quarantined_deliveries ?? '—'} Quarantine delivery(s)
              </small>
              <small className="muted">
                {metrics?.oldest_pending_age_seconds != null
                  ? `Older: ${Math.floor(metrics.oldest_pending_age_seconds / 60)} min`
                  : metrics ? (metrics.queued_deliveries===0 ? "Queue empty" : "Oldest pending age unavailable") : "Queue status unavailable"}
              </small>
            </section>
            <section>
              <span>Available disk space</span>
              <strong>
                {metrics
                  ? (metrics.disk_available_bytes / 1024 ** 3).toFixed(1)
                  : '—'}{' '}
                <small>GiB</small>
              </strong>
              <small className="muted">
                Maximum latency: {metrics?.max_analysis_ms_last_hour ?? '—'}{' '}
                ms on the last hour
              </small>
            </section>
          </div>
          <div className="server-facts">
            <span>
              <strong>{config.max_connections}</strong> SMTP connections
            </span>
            <span>
              <strong>{config.processing}</strong> simultaneous analyses
            </span>
            <span>
              <strong>{config.relay_workers}</strong> simultaneous deliveries
            </span>
            <span>
              <strong>
                {Math.round(config.max_message_bytes / 1024 ** 2)} MiB
              </strong>{' '}
              per message
            </span>
          </div>
          {metrics?.llm_budget && <LlmPricingNotice checkedAt={metrics.llm_budget.pricing_checked_at} />}
          {metrics?.llm_budget && (
            <p className="notice">
              Scaleway analysis:{' '}
              {(metrics.llm_budget.accounted_micro_eur / 1e6).toFixed(2)} € recorded on{' '}
              {(metrics.llm_budget.monthly_budget_micro_eur / 1e6).toFixed(2)} € per month · {metrics.llm_budget.requests} requests.
            </p>
          )}
          <section className="panel">
            <h2>Delivery queue</h2>
            <p className="muted small">
              The first 200 unresolved deliveries. Temporary failures are retried for up to five days.
            </p>
            {!operationView ? <output>Loading the delivery queue…</output> : operationView.queueError ? <p role="alert" className="error">{operationView.queueError} Queue state is unavailable; it is not confirmed empty.</p> : !deliveries.length ? (
              <div className="empty compact">
                <CheckCircle2 size={28} />
                <h2>No message pending</h2>
                <p>The next deliveries to be monitored will appear here.</p>
              </div>
            ) : (
              <div className="table-scroll">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th>Recipient</th>
                      <th>State</th>
                      <th>Attempts</th>
                      <th>Next retry</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deliveries.map((d) => (
                      <tr key={d.id}>
                        <td className="wrap">
                          <strong>{d.address}</strong>
                          <small>
                            {d.node_id || "Local server"}
                            {d.pending_command ? " · Pending commands" : ''}
                          </small>
                          <small className="queue-error">
                            {d.error || "No error recorded"}
                          </small>
                        </td>
                        <td>
                          {
                            {
                              pending: "Pending",
                              sending: "In progress",
                              failed: "Final failure",
                            }[d.status]
                          }
                        </td>
                        <td>{d.attempts}</td>
                        <td>
                          {d.status === 'pending' ? stamp(d.next_attempt) : '—'}
                        </td>
                        <td>
                          <Button
                            variant="outline"
                            disabled={
                              busy ||
                              d.status !== 'pending' ||
                              d.pending_command
                            }
                            onClick={() =>
                              void action(async () => {
                                const result = await api<{ status?: string }>(
                                  '/admin/queue/retry',
                                  { id: d.id },
                                  user.csrf,
                                );
                                setEpoch((e) => e + 1);
                                setNotice(
                                  result.status === 'queued'
                                    ? "Relaunch transmitted to the original server; confirmation pending."
                                    : "Delivery scheduled for immediate retry.",
                                );
                              })
                            }
                          >
                            Retry
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <SettingsHistory owner={user.username} revision={config.revision} settings={config.settings} epoch={epoch} dirty={dirty} busy={busy || refreshRequired}
            onLoad={(value,label)=>{setDraft(value);setModelChoice(null);setReviewed(null);setEpoch(e=>e+1);setNotice(`${label} loaded as an unsaved draft. Review before applying as a new revision.`);}} />
        </>
      )}
      {dirty && (
        <div className="save-area">
          {review && proposal && (
            <section className="change-review">
              <h2 ref={reviewHeading} tabIndex={-1}>Review configuration changes</h2>
              {modelSelection && <p className="notice">Explicit {catalogSelection ? 'retained' : 'server'} model-file selection: <code>{modelSelection}</code>. File bytes and activation prerequisites are checked again by the server.</p>}
              {catalogSelection && <p className="notice">The shadow candidate follows the retained preview, including explicit absence. Its role remains observation only.</p>}
              <SettingsComparison before={config.settings} after={proposal.settings} beforeLabel={`Loaded revision ${config.revision}`} afterLabel="Proposed settings"/>
              <p className="small muted">{activation.view?.coordinated ? 'Activation waits for every MX. New SMTP acceptance may be temporarily deferred.' : 'Applies to future messages.'} Already accepted deliveries keep their recorded decisions. Saving revalidates permissions, configuration and the base revision.</p>
            </section>
          )}
          {reviewed && !review && <p className="notice">The draft, base revision or selected model files changed. Review again before applying.</p>}
          <div className="save-bar">
            <span>
              <strong>Unsaved changes</strong>
              <small>Initial revision: {config.revision}</small>
            </span>
            <div>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setDiscard(true);
                }}
              >
                <RotateCcw size={16} />
                Cancel
              </Button>
              <Button
                disabled={busy || blocked || setupOpen}
                onClick={() => {
                  if (review) void action(save);
                  else {setReviewed(reviewKey);requestAnimationFrame(()=>reviewHeading.current?.focus());}
                }}
              >
                <Save size={16} />
                {busy
                  ? "Submitting…"
                  : review
                    ? activation.view?.coordinated ? "Stage settings" : "Apply settings"
                    : "Review and apply"}
              </Button>
            </div>
          </div>
        </div>
      )}
      </fieldset>
      {discard && <ConfirmDialog title="Discard unsaved configuration?" confirmLabel="Discard and reload" danger busy={busy} onCancel={()=>setDiscard(false)} onConfirm={()=>{setDiscard(false);void action(async()=>{await reload();setNotice('Draft discarded; installed settings reloaded.');requestAnimationFrame(()=>pageHeading.current?.focus());});}}><p>Replace the current draft with the installed settings. This does not undo any saved revision.</p></ConfirmDialog>}
    </div>
  );
}
