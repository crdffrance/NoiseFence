'use client';
import { useEffect, useState, type ReactNode } from 'react';
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
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';

export const navigation = [
  { id: 'messages', label: 'Messages', icon: Activity },
  { id: 'domains', label: 'Domaines', icon: Globe2 },
  { id: 'gateways', label: 'Passerelles', icon: Network },
  { id: 'filters', label: 'Filtres', icon: SlidersHorizontal },
  { id: 'users', label: 'Comptes & accès', icon: Users },
  { id: 'server', label: 'État du serveur', icon: Server },
] as const;
export type Section = (typeof navigation)[number]['id'];
type Gateway = { id: string; name: string; hosts: string[]; port: number };
type Domain = {
  name: string;
  gateway: string | null;
  enabled: boolean;
  accept_all_recipients: boolean;
  recipients: string[];
  aliases: Record<string, string>;
};
type Filters = {
  mode: 'observe' | 'tag';
  threshold: number;
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
type Settings = { domains: Domain[]; gateways: Gateway[]; filters: Filters };
type Configuration = {
  revision: number;
  settings: Settings;
  available: Filters;
  threshold_locked: boolean;
  tag_ready: boolean;
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
type Revision = { id: number; created: number; username: string };
type Audit = {
  created: number;
  username: string;
  action: string;
  object: string;
};
type Delivery = {
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
  unnotified_failures: number;
  oldest_pending_age_seconds: number | null;
  received_last_hour: number;
  incomplete_last_hour: number;
  max_analysis_ms_last_hour: number;
  disk_available_bytes: number;
  llm_budget?: {
    accounted_micro_eur: number;
    monthly_budget_micro_eur: number;
    requests: number;
  };
};
const modules: {
  key: keyof Omit<Filters, 'mode' | 'threshold'>;
  title: string;
  description: string;
}[] = [
  {
    key: 'authentication',
    title: 'Authentification des e-mails',
    description: 'SPF, DKIM, DMARC et ARC, vérifiés avant toute modification.',
  },
  {
    key: 'semantic',
    title: 'Compréhension multilingue',
    description:
      'Modèle local : combine le sens du message et les indices textuels.',
  },
  {
    key: 'antivirus',
    title: 'Antivirus',
    description: 'Recherche de fichiers malveillants dans les pièces jointes.',
  },
  {
    key: 'signatures',
    title: 'Signatures complémentaires',
    description: 'Détection locale de campagnes et de contenus suspects.',
  },
  {
    key: 'smtp_policy',
    title: 'Cohérence SMTP & DNS',
    description:
      'Identité du serveur, reverse DNS et cohérence de l’expéditeur.',
  },
  {
    key: 'vision',
    title: 'OCR, QR codes & codes-barres',
    description:
      'Lecture locale des images et PDF, sans ouvrir les liens détectés.',
  },
  {
    key: 'reputation',
    title: 'Réputation Spamhaus DQS',
    description:
      'Réputation des IP et domaines, avec la clé configurée sur le serveur.',
  },
  {
    key: 'llm',
    title: 'Analyse complémentaire Scaleway',
    description:
      'Service externe pour les messages dans la plage configurée, soumis au budget mensuel.',
  },
];
const stamp = (n: number) => new Date(n * 1000).toLocaleString('fr-FR');
const lines = (s: string) =>
  s
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);
function normalize(s: Settings): Settings {
  return {
    ...s,
    gateways: s.gateways.map((g) => ({
      ...g,
      name: g.name.trim(),
      hosts: g.hosts.map((h) => h.trim().toLowerCase()).filter(Boolean),
    })),
    domains: s.domains.map((d) => ({
      ...d,
      name: d.name.trim().toLowerCase(),
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
      Alias explicites{' '}
      <small>Une ligne par alias : adresse@domaine = destination@domaine</small>
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
              setError('Utilisez le séparateur « = » entouré d’espaces.');
              onChange({ '': text });
              return;
            }
            const key = line.slice(0, i).trim();
            if (key in result) {
              setError('Un alias est présent plusieurs fois.');
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
  onApplied,
  onDomain,
}: {
  user: User;
  section: Section;
  onDirty: (v: boolean) => void;
  onApplied: () => Promise<void>;
  onDomain: (name: string) => void;
}) {
  const [config, setConfig] = useState<Configuration | null>(null),
    [draft, setDraft] = useState<Settings | null>(null);
  const [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false),
    [review, setReview] = useState(false);
  const [accounts, setAccounts] = useState<Account[]>([]),
    [editing, setEditing] = useState<Account | null>(null),
    [password, setPassword] = useState('');
  const [metrics, setMetrics] = useState<Metrics | null>(null),
    [deliveries, setDeliveries] = useState<Delivery[]>([]),
    [audit, setAudit] = useState<Audit[]>([]),
    [revisions, setRevisions] = useState<Revision[]>([]);
  const [epoch, setEpoch] = useState(0);
  const dirty =
    !!config &&
    !!draft &&
    JSON.stringify(config.settings) !== JSON.stringify(draft);
  useEffect(() => {
    onDirty(dirty);
    const leave = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener('beforeunload', leave);
    return () => window.removeEventListener('beforeunload', leave);
  }, [dirty, onDirty]);
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
    if (section === 'server')
      Promise.all([
        api<Metrics>('/metrics'),
        api<Delivery[]>('/admin/queue'),
        api<Audit[]>('/admin/audit'),
        api<Revision[]>('/admin/revisions'),
      ])
        .then(([m, d, a, r]) => {
          if (active) {
            setMetrics(m);
            setDeliveries(d);
            setAudit(a);
            setRevisions(r);
          }
        })
        .catch((e) => {
          if (active) setError(e.message);
        });
    return () => {
      active = false;
    };
  }, [section, user, epoch]);
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function reload() {
    const c = await api<Configuration>('/admin/config');
    setConfig(c);
    setDraft(c.settings);
    setReview(false);
    setEpoch((e) => e + 1);
  }
  async function save() {
    if (!config || !draft) return;
    await api(
      '/admin/config',
      { revision: config.revision, settings: normalize(draft) },
      user.csrf,
    );
    await reload();
    setNotice(
      'Réglages appliqués. Ils seront utilisés dès le prochain message.',
    );
    await onApplied();
  }
  if (!config || !draft)
    return (
      <div className="panel">
        {error ? (
          <p role="alert" className="error">
            {error}
          </p>
        ) : (
          <p className="muted">Chargement de l’administration…</p>
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
  const changedDomains = draft.domains.filter(
    (d) =>
      JSON.stringify(d) !==
      JSON.stringify(
        config.settings.domains.find((old) => old.name === d.name),
      ),
  );
  const removed = config.settings.domains.filter(
    (d) => !draft.domains.some((n) => n.name === d.name),
  );
  const changedGateways = draft.gateways.filter(
    (g) =>
      JSON.stringify(g) !==
      JSON.stringify(config.settings.gateways.find((old) => old.id === g.id)),
  );
  const removedGateways = config.settings.gateways.filter(
    (g) => !draft.gateways.some((n) => n.id === g.id),
  );
  return (
    <div className="admin-console">
      <div className="page-heading">
        <div>
          <p className="eyebrow">
            {section === 'server' ? 'EXPLOITATION' : 'ADMINISTRATION'}
          </p>
          <h1>{navigation.find((n) => n.id === section)?.label}</h1>
          <p className="muted">
            {
              {
                domains:
                  'Les domaines qui peuvent recevoir des messages sur votre passerelle.',
                gateways:
                  'Les serveurs de destination, dans leur ordre de priorité.',
                filters:
                  'Une politique commune pour un filtrage cohérent sur tous vos domaines.',
                users:
                  'Des accès individuels, par adresse ou pour un domaine entier.',
                server: 'Livraisons, capacité et historique des changements.',
                messages: '',
              }[section]
            }
          </p>
        </div>
        <span className="revision-badge">Révision {config.revision}</span>
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
      {section === 'domains' && (
        <>
          <div className="admin-summary">
            <span>
              <Globe2 size={19} />
              <strong>
                {draft.domains.filter((d) => d.enabled).length}
              </strong>{' '}
              domaines actifs
            </span>
            <span>
              <Network size={19} />
              <strong>{draft.gateways.length}</strong> passerelles disponibles
            </span>
            <Button
              onClick={() =>
                setDraft({
                  ...draft,
                  domains: [
                    ...draft.domains,
                    {
                      name: '',
                      gateway: draft.gateways[0]?.id ?? null,
                      enabled: true,
                      accept_all_recipients: true,
                      recipients: [],
                      aliases: {},
                    },
                  ],
                })
              }
            >
              <Plus size={16} />
              Ajouter un domaine
            </Button>
          </div>
          <div className="notice">
            Pour recevoir les e-mails, le domaine doit également être configuré
            chez votre hébergeur de messagerie. Après validation de la
            livraison, son DNS devra pointer vers {config.hostname}.
          </div>
          <div className="admin-cards">
            {draft.domains.map((d, i) => (
              <ConfigCard key={`${epoch}-${i}`} newItem={!d.name}>
                <summary>
                  <span className="card-icon">
                    <Globe2 size={21} />
                  </span>
                  <span className="card-title">
                    <strong>{d.name || 'Nouveau domaine'}</strong>
                    <small>
                      {d.accept_all_recipients
                        ? 'Toutes les adresses acceptées'
                        : `${d.recipients.length} adresse(s) explicite(s)`}{' '}
                      · {Object.keys(d.aliases).length} alias
                    </small>
                  </span>
                  <span className={`status ${d.enabled ? 'good' : ''}`}>
                    {d.enabled ? 'Actif' : 'Désactivé'}
                  </span>
                </summary>
                <div className="card-body">
                  <div className="form-grid">
                    <label className="field" htmlFor={`domain-name-${i}`}>
                      Nom de domaine
                      <Input
                        id={`domain-name-${i}`}
                        value={d.name}
                        placeholder="exemple.fr"
                        onChange={(e) => domainAt(i, { name: e.target.value })}
                        spellCheck={false}
                      />
                    </label>
                    <label className="field">
                      Passerelle de livraison
                      <select
                        value={d.gateway ?? ''}
                        onChange={(e) =>
                          domainAt(i, { gateway: e.target.value || null })
                        }
                      >
                        <option value="">Alias uniquement</option>
                        {draft.gateways.map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name || 'Nouvelle passerelle'}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <Toggle
                    label="Réception activée"
                    description="Un domaine désactivé refuse les nouveaux destinataires SMTP."
                    checked={d.enabled}
                    onChange={(enabled) => domainAt(i, { enabled })}
                  />
                  <Toggle
                    label="Accepter toutes les adresses du domaine"
                    description={`Aucune déclaration par boîte : *@${d.name || 'exemple.fr'}. La destination finale doit accepter ces adresses.`}
                    checked={d.accept_all_recipients}
                    onChange={(accept_all_recipients) =>
                      domainAt(i, { accept_all_recipients })
                    }
                  />
                  {!d.accept_all_recipients && (
                    <label className="field">
                      Adresses autorisées
                      <small>Une adresse complète par ligne.</small>
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
                      Voir les messages
                      <ArrowUpRight size={15} />
                    </Button>
                    <Button
                      variant="ghost"
                      className="danger"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Retirer ${d.name || 'ce domaine'} ? Les messages déjà acceptés continueront leur livraison.`,
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
                      Retirer
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
              TLS vérifié vers les serveurs publics
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
              Ajouter une passerelle
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
                    <strong>{g.name || 'Nouvelle passerelle'}</strong>
                    <small>
                      {g.hosts.filter(Boolean).join(' → ') ||
                        'Destination à renseigner'}
                    </small>
                  </span>
                  <span className="status">Port {g.port}</span>
                </summary>
                <div className="card-body">
                  <div className="form-grid">
                    <label className="field" htmlFor={`gateway-name-${i}`}>
                      Nom de la passerelle
                      <Input
                        id={`gateway-name-${i}`}
                        value={g.name}
                        onChange={(e) => gatewayAt(i, { name: e.target.value })}
                        placeholder="Proton Mail"
                      />
                    </label>
                    <label className="field" htmlFor={`gateway-port-${i}`}>
                      Port SMTP
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
                    Serveurs de réception
                    <small>
                      Un nom DNS par ligne. Premier serveur prioritaire, puis
                      serveurs de secours. Un suffixe :port peut remplacer le
                      port commun.
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
                    Domaines associés :{' '}
                    {draft.domains
                      .filter((d) => d.gateway === g.id)
                      .map((d) => d.name)
                      .join(', ') || 'Aucun'}
                    . Les nouvelles routes s’appliquent aux futurs messages ;
                    les livraisons déjà en file conservent leur destination.
                  </p>
                  <div className="card-actions">
                    <span className="small muted">
                      Chiffrement et vérification du certificat obligatoires
                    </span>
                    <Button
                      variant="ghost"
                      className="danger"
                      disabled={draft.domains.some((d) => d.gateway === g.id)}
                      onClick={() => {
                        if (
                          window.confirm(
                            'Retirer cette passerelle inutilisée ?',
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
                      Retirer
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
          <div className="panel filter-policy">
            <div>
              <h2>Comportement du filtre</h2>
              <p className="muted small">
                Les messages sont transmis. En mode marquage, les messages
                classés indésirables reçoivent le préfixe [SPAM].
              </p>
            </div>
            <div className="form-grid">
              <label className="field">
                Mode de fonctionnement
                <select
                  value={draft.filters.mode}
                  onChange={(e) =>
                    filterAt('mode', e.target.value as Filters['mode'])
                  }
                >
                  <option value="observe">
                    Observation — analyser et transmettre
                  </option>
                  <option value="tag">Marquage — ajouter [SPAM]</option>
                </select>
              </label>
              <label className="field" htmlFor="filter-threshold">
                Seuil de classement / 100
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
                    ? 'Seuil lié à la calibration du modèle multilingue. Une nouvelle calibration est requise pour le modifier.'
                    : 'Un seuil plus élevé réduit le nombre de messages marqués.'}
                </small>
              </label>
            </div>
            {!config.tag_ready && (
              <p className="notice">
                Le marquage nécessite la validation de la livraison Proton et la
                configuration ARC. Le serveur refusera son activation tant que
                ces conditions ne sont pas remplies.
              </p>
            )}
          </div>
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
                    ? 'À configurer sur le serveur'
                    : draft.filters[m.key]
                      ? 'Activé'
                      : 'Désactivé'}
                </span>
              </section>
            ))}
          </div>
          <section className="panel">
            <h2>Contribution au score</h2>
            <p className="muted small">
              L’observation enregistre les indices. Activer leur contribution
              change le classement des futurs messages et demande une validation
              de la qualité.
            </p>
            <Toggle
              label="Indices SMTP et DNS dans le score"
              checked={draft.filters.smtp_policy_scoring}
              disabled={!draft.filters.smtp_policy}
              onChange={(v) => filterAt('smtp_policy_scoring', v)}
            />
            <Toggle
              label="Texte OCR et liens décodés dans le score"
              checked={draft.filters.vision_scoring}
              disabled={!draft.filters.vision}
              onChange={(v) => filterAt('vision_scoring', v)}
            />
          </section>
        </>
      )}
      {section === 'users' && (
        <>
          <div className="admin-summary">
            <span>
              <Users size={19} />
              <strong>{accounts.length}</strong> comptes ·{' '}
              {accounts.filter((a) => a.admin && !a.disabled).length}{' '}
              administrateur(s) actif(s)
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
              Créer un compte
            </Button>
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
                    'Compte enregistré. Les sessions précédentes de ce compte ont été révoquées.',
                  );
                  if (self) window.dispatchEvent(new Event('session-expired'));
                });
              }}
            >
              <h2>
                {editing.version < 0
                  ? 'Créer un compte'
                  : `Modifier ${editing.username}`}
              </h2>
              <div className="form-grid">
                <label className="field" htmlFor="account-name">
                  Identifiant
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
                    ? 'Mot de passe'
                    : 'Nouveau mot de passe (facultatif)'}
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
                label="Administrateur de l’organisation"
                description="Peut modifier la configuration et consulter tous les messages de tous les domaines."
                checked={editing.admin}
                onChange={(admin) => setEditing({ ...editing, admin })}
              />
              {!editing.admin && (
                <label className="field">
                  Adresses et domaines autorisés
                  <small>
                    Une adresse par ligne ; utilisez *@exemple.fr pour donner
                    accès à tout un domaine déjà enregistré.
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
                    placeholder={'alice@exemple.fr\n*@autre-domaine.fr'}
                  />
                </label>
              )}
              <Toggle
                label="Compte désactivé"
                description="La connexion est refusée et les sessions existantes sont révoquées à l’enregistrement."
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
                  Annuler
                </Button>
                <Button disabled={busy} type="submit">
                  Enregistrer le compte
                </Button>
              </div>
            </form>
          )}
          <div className="panel table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Compte</th>
                  <th>Rôle</th>
                  <th>Accès</th>
                  <th>État</th>
                  <th>
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.username}>
                    <td>
                      <strong>{a.username}</strong>
                      {a.username === user.username && (
                        <small className="muted"> · Vous</small>
                      )}
                    </td>
                    <td>{a.admin ? 'Administrateur' : 'Utilisateur'}</td>
                    <td className="wrap">
                      {a.admin
                        ? 'Tous les domaines'
                        : a.addresses.join(', ') || 'Aucun accès'}
                    </td>
                    <td>
                      <span className={`status ${a.disabled ? '' : 'good'}`}>
                        {a.disabled ? 'Désactivé' : 'Actif'}
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
                        Modifier
                      </Button>
                    </td>
                  </tr>
                ))}
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
              Actualiser
            </Button>
          </div>
          <div className="stats">
            <section>
              <span>Messages · dernière heure</span>
              <strong>{metrics?.received_last_hour ?? '—'}</strong>
              <small className="muted">
                {metrics?.incomplete_last_hour ?? '—'} analyses incomplètes
              </small>
            </section>
            <section>
              <span>Livraisons en attente</span>
              <strong>{metrics?.queued_deliveries ?? '—'}</strong>
              <small className="muted">
                {metrics?.oldest_pending_age_seconds != null
                  ? `Plus ancienne : ${Math.floor(metrics.oldest_pending_age_seconds / 60)} min`
                  : 'File sans attente'}
              </small>
            </section>
            <section>
              <span>Espace disque disponible</span>
              <strong>
                {metrics
                  ? (metrics.disk_available_bytes / 1024 ** 3).toFixed(1)
                  : '—'}{' '}
                <small>Gio</small>
              </strong>
              <small className="muted">
                Latence maximale : {metrics?.max_analysis_ms_last_hour ?? '—'}{' '}
                ms sur la dernière heure
              </small>
            </section>
          </div>
          <div className="server-facts">
            <span>
              <strong>{config.max_connections}</strong> connexions SMTP
            </span>
            <span>
              <strong>{config.processing}</strong> analyses simultanées
            </span>
            <span>
              <strong>{config.relay_workers}</strong> livraisons simultanées
            </span>
            <span>
              <strong>
                {Math.round(config.max_message_bytes / 1024 ** 2)} Mio
              </strong>{' '}
              par message
            </span>
          </div>
          {metrics?.llm_budget && (
            <p className="notice">
              Analyse Scaleway :{' '}
              {(metrics.llm_budget.accounted_micro_eur / 1e6).toFixed(2)} €
              comptabilisés sur{' '}
              {(metrics.llm_budget.monthly_budget_micro_eur / 1e6).toFixed(2)} €
              par mois · {metrics.llm_budget.requests} demande(s).
            </p>
          )}
          <section className="panel">
            <h2>File de livraison</h2>
            <p className="muted small">
              200 premières livraisons non résolues. Les erreurs temporaires
              sont réessayées automatiquement pendant cinq jours.
            </p>
            {!deliveries.length ? (
              <div className="empty compact">
                <CheckCircle2 size={28} />
                <h2>Aucun message en attente</h2>
                <p>Les prochaines livraisons à surveiller apparaîtront ici.</p>
              </div>
            ) : (
              <div className="table-scroll">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th>Destinataire</th>
                      <th>État</th>
                      <th>Tentatives</th>
                      <th>Prochain essai</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deliveries.map((d) => (
                      <tr key={d.id}>
                        <td className="wrap">
                          <strong>{d.address}</strong>
                          <small className="queue-error">
                            {d.error || 'Aucune erreur enregistrée'}
                          </small>
                        </td>
                        <td>
                          {
                            {
                              pending: 'En attente',
                              sending: 'En cours',
                              failed: 'Échec définitif',
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
                            disabled={busy || d.status !== 'pending'}
                            onClick={() =>
                              void action(async () => {
                                await api(
                                  '/admin/queue/retry',
                                  { id: d.id },
                                  user.csrf,
                                );
                                setEpoch((e) => e + 1);
                                setNotice(
                                  'Livraison remise à échéance immédiate.',
                                );
                              })
                            }
                          >
                            Réessayer
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <div className="admin-two-columns">
            <section className="panel">
              <h2>Historique des réglages</h2>
              <p className="muted small">
                Chargez une ancienne configuration, examinez-la puis
                appliquez-la comme une nouvelle révision.
              </p>
              <div className="revision-list">
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() =>
                    void action(async () => {
                      if (
                        dirty &&
                        !window.confirm(
                          'Remplacer les modifications non appliquées ?',
                        )
                      )
                        return;
                      setDraft(await api<Settings>('/admin/revisions/0'));
                      setEpoch((e) => e + 1);
                      setNotice(
                        'Configuration initiale chargée. Vérifiez les modifications avant application.',
                      );
                    })
                  }
                >
                  Charger la configuration initiale
                </Button>
                {revisions.map((r) => (
                  <div key={r.id}>
                    <span>
                      <strong>Révision {r.id}</strong>
                      <small>
                        {stamp(r.created)} · {r.username}
                      </small>
                    </span>
                    <Button
                      variant="ghost"
                      disabled={busy || r.id === config.revision}
                      onClick={() =>
                        void action(async () => {
                          if (
                            dirty &&
                            !window.confirm(
                              'Remplacer les modifications non appliquées ?',
                            )
                          )
                            return;
                          setDraft(
                            await api<Settings>(`/admin/revisions/${r.id}`),
                          );
                          setEpoch((e) => e + 1);
                          setNotice(`Révision ${r.id} chargée pour examen.`);
                        })
                      }
                    >
                      {r.id === config.revision ? 'Active' : 'Charger'}
                    </Button>
                  </div>
                ))}
              </div>
            </section>
            <section className="panel">
              <h2>Journal d’administration</h2>
              <p className="muted small">
                Les 200 derniers événements enregistrés.
              </p>
              <div className="audit-list">
                {audit.map((a, i) => (
                  <div key={i}>
                    <span className="audit-dot" />
                    <div>
                      <strong>
                        {{
                          configuration: 'Réglages appliqués',
                          account: 'Compte modifié',
                          retry: 'Livraison relancée',
                          login: 'Connexion',
                          feedback: 'Correction de classement',
                        }[a.action] || a.action}
                      </strong>
                      <p>
                        {a.username}
                        {a.object && ` · ${a.object}`}
                      </p>
                      <small>{stamp(a.created)}</small>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </>
      )}
      {dirty && (
        <div className="save-area">
          {review && (
            <section className="change-review">
              <h2>Vérifier les modifications</h2>
              <ul>
                {changedDomains.map((d, i) => (
                  <li key={`d${i}`}>
                    Domaine <strong>{d.name || '(nom manquant)'}</strong> :{' '}
                    {d.enabled ? 'activé' : 'désactivé'},{' '}
                    {d.accept_all_recipients
                      ? 'toutes les adresses'
                      : `${d.recipients.filter(Boolean).length} adresses`}
                    , passerelle{' '}
                    {draft.gateways.find((g) => g.id === d.gateway)?.name ||
                      'alias uniquement'}
                    , {Object.keys(d.aliases).length} alias.
                  </li>
                ))}
                {removed.map((d) => (
                  <li key={d.name}>
                    Retrait du domaine <strong>{d.name}</strong>.
                  </li>
                ))}
                {changedGateways.map((g) => (
                  <li key={g.id}>
                    Passerelle <strong>{g.name || '(nom manquant)'}</strong> :{' '}
                    {g.hosts.join(' → ')} · port {g.port}.
                  </li>
                ))}
                {removedGateways.map((g) => (
                  <li key={g.id}>
                    Retrait de la passerelle <strong>{g.name}</strong>.
                  </li>
                ))}
                {Object.entries(draft.filters)
                  .filter(
                    ([k, v]) =>
                      v !== config.settings.filters[k as keyof Filters],
                  )
                  .map(([k, v]) => (
                    <li key={k}>
                      {(
                        {
                          mode: 'Mode de fonctionnement',
                          threshold: 'Seuil de classement',
                          smtp_policy_scoring: 'Contribution SMTP',
                          vision_scoring: 'Contribution OCR',
                        } as Record<string, string>
                      )[k] ||
                        modules.find((m) => m.key === k)?.title ||
                        k}{' '}
                      :{' '}
                      <strong>
                        {typeof v === 'boolean'
                          ? v
                            ? 'activé'
                            : 'désactivé'
                          : v === 'tag'
                            ? 'marquage'
                            : v === 'observe'
                              ? 'observation'
                              : v}
                      </strong>
                      .
                    </li>
                  ))}
              </ul>
              <p className="small muted">
                Application immédiate aux prochains messages. Les livraisons
                déjà acceptées sont conservées.
              </p>
            </section>
          )}
          <div className="save-bar">
            <span>
              <strong>Modifications non appliquées</strong>
              <small>Révision de départ : {config.revision}</small>
            </span>
            <div>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  if (
                    window.confirm(
                      'Abandonner les modifications et recharger les réglages actifs ?',
                    )
                  )
                    void action(reload);
                }}
              >
                <RotateCcw size={16} />
                Annuler
              </Button>
              <Button
                disabled={busy}
                onClick={() => {
                  if (review) void action(save);
                  else setReview(true);
                }}
              >
                <Save size={16} />
                {busy
                  ? 'Application…'
                  : review
                    ? 'Appliquer les réglages'
                    : 'Vérifier et appliquer'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
