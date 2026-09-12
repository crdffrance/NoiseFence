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
  authentication: 'Authentification',
  bayes: 'Statistiques Bayes',
  campaign: 'Campagnes',
  content: 'Contenu',
  lexical: 'Texte',
  other: 'Autres signaux',
  reputation: 'Réputation',
  semantic: 'Analyse sémantique',
  smtp: 'Identité SMTP',
  protection: 'Réputation CRDF / VirusTotal et liens',
  url_resolution: 'Suivi des redirections URL',
  max_urls: 'URLs à suivre par message',
  max_redirects: 'Redirections maximales',
  blocked_ips: 'Adresses IP exclues du suivi',
  analysis: 'Analyse des messages',
  llm: 'Intelligence artificielle · Scaleway',
  vision: 'Images, OCR et QR codes',
  smtp_policy: 'Identité SMTP et DNS',
  native: 'Règles natives Rust',
  model: 'Modèle',
  project_id: 'Identifiant du projet Scaleway',
  monthly_budget_micro_eur: 'Budget mensuel (€)',
  input_micro_eur_per_million: 'Prix d’entrée (€ / million de jetons)',
  output_micro_eur_per_million: 'Prix de sortie (€ / million de jetons)',
  pricing_checked_at: 'Date de vérification des tarifs (UTC)',
  timeout_ms: 'Délai maximal (ms)',
  max_text_bytes: 'Texte maximal envoyé (octets)',
  max_output_tokens: 'Réponse maximale (jetons)',
  score_low: 'Score minimal sélectionné',
  score_high: 'Score maximal sélectionné',
  review_unconfirmed_high: 'Examiner aussi les scores élevés non confirmés',
  max_parallel: 'Analyses simultanées',
  cache_entries: 'Entrées du cache',
  cache_ttl_seconds: 'Durée maximale du cache (secondes)',
  max_bytes: 'Taille maximale analysée (octets)',
  max_parts: 'Pièces jointes analysées',
  max_part_bytes: 'Taille maximale par pièce (octets)',
  max_total_bytes: 'Taille totale maximale (octets)',
  max_pixels: 'Pixels maximaux',
  max_pages: 'Pages maximales',
  max_text_chars: 'Caractères reconnus',
  max_codes: 'Codes reconnus',
  fuzzy_memory: 'Mémoire des campagnes similaires',
  content_rules: 'Règles de contenu',
  patterns: 'Motifs textuels',
  composites: 'Combinaisons de signaux',
  caps: 'Plafonds par famille',
  enabled: 'Activé',
  disabled: 'Règles désactivées',
  weights: 'Poids personnalisés',
  min: 'Minimum',
  max: 'Maximum',
  minimum_providers: 'Fournisseurs indépendants requis',
  minimum_threshold: 'Seuil personnel minimal',
  maximum_threshold: 'Seuil personnel maximal',
  max_rules: 'Règles par adresse ou domaine',
  allowed_actions: 'Actions autorisées',
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
          <span>Bloc modifié, à valider avant l’enregistrement global.</span>
          <Button
            variant="outline"
            onClick={() => {
              try {
                onChange(JSON.parse(text));
                setText(null);
                setError('');
              } catch (e) {
                setError(`Bloc refusé : ${(e as Error).message}`);
              }
            }}
          >
            Valider ce bloc JSON
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              setText(null);
              setError('');
            }}
          >
            Annuler le bloc
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
      <summary>{label} · réglage avancé</summary>
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
      <legend>Règles HTML, MIME et pièces jointes</legend>
      <label className="setting-toggle">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(e) => onChange({ ...value, enabled: e.target.checked })}
        />
        Activer les règles de contenu
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
              Poids · {r.id}
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
        Rétablir les règles natives
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
          <h2>Paramètres des moteurs</h2>
          <p>
            Réglages appliqués aux nouveaux messages. L’activation de chaque
            moteur se règle dans « Moteurs de détection ».
          </p>
        </div>
      </div>
      <input
        aria-label="Rechercher un paramètre"
        placeholder="Rechercher : budget, OCR, cache, délai…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <p className="notice">
        Le LLM transmet le texte sélectionné à Scaleway. 0–100 sélectionne tous
        les messages analysables. Le budget, la taille transmise et les tarifs
        ci-dessous déterminent le coût ; une indisponibilité ne constitue jamais
        une preuve de spam.
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
              .toLocaleLowerCase('fr')
              .includes(query.toLocaleLowerCase('fr')),
          );
        if (!entries.length) return null;
        return (
          <section key={module} className="management-card">
            <h3>{labels[module] ?? module}</h3>
            {module === 'native' && (
              <p>
                Ce moteur reste en observation. Les motifs liés à un modèle
                adaptatif sont protégés par sa validation.
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
      <h2>Réputation IP · RBL</h2>
      <p>
        Contrôles avant DATA. Seuls les codes de réponse déclarés comptent ; une
        erreur DNS reste indisponible. Les zones d’un même fournisseur comptent
        pour une seule voix.
      </p>
      <div className="management-card">
        <div className="management-grid">
          <label>
            Action si les fournisseurs concordent
            <select
              value={value.action}
              onChange={(e) =>
                onChange({
                  ...value,
                  action: e.target.value as RblSettings['action'],
                })
              }
            >
              <option value="observe">Observer</option>
              <option value="defer">Différer · SMTP 451</option>
              <option value="reject">Refuser · SMTP 550</option>
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
          Le mode global Observation neutralise les refus et reports. Le
          contrôle RBL ne lit pas le contenu des messages.
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
          Ajouter une liste
        </Button>
      </div>
      <p>
        Chaque ajout est désactivé. Vérifiez les conditions du fournisseur avant
        activation ; Barracuda nécessite un accès enregistré. Spamhaus DQS
        utilise le connecteur dédié. Les URIBL ne sont pas des listes IP.
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
              <strong>{list.id || 'Nouvelle liste'}</strong>
            </label>
            <Button
              aria-label={`Supprimer ${list.id}`}
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
                  ? 'Identifiant'
                  : k === 'provider'
                    ? 'Fournisseur indépendant'
                    : 'Zone DNS'}
                <input
                  value={list[k]}
                  onChange={(e) => update(i, { [k]: e.target.value })}
                />
              </label>
            ))}
            <label>
              Codes de classement (séparés par des virgules)
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
              Codes de politique à observer
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
              IPv6 pris en charge
            </label>
          </div>
          {list.key_env && (
            <small>Clé serveur déclarée · destination protégée</small>
          )}
        </section>
      ))}
      <section className="management-card">
        <h3>Tester ce brouillon</h3>
        <p>
          Interroge les listes activées pour cette IP, sans envoyer d’email ni
          enregistrer les réglages.
        </p>
        <div className="management-toolbar">
          <input
            aria-label="IP publique à tester"
            placeholder="Adresse IP publique"
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
            {busy ? 'Test en cours…' : 'Tester'}
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
      <h2>Personnalisation par les utilisateurs</h2>
      <p>
        Les préférences appartiennent à l’adresse ou au domaine. Chaque
        modification exige un droit d’accès actuel. Les règles de
        l’administrateur, l’antivirus et le mode global restent prioritaires.
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
        <legend>Actions proposées aux utilisateurs</legend>
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
              ? 'Transmettre'
              : a === 'tag'
                ? 'Marquer'
                : 'Mettre en quarantaine'}
          </label>
        ))}
      </fieldset>
      <p>
        {Object.keys(value.mailboxes).length} portées personnalisées. Réduire
        les droits exige de rendre les préférences existantes compatibles.
      </p>
      {Object.entries(value.mailboxes).map(([scope, p]) => (
        <details className="management-card" key={scope}>
          <summary>
            {scope} · {p.rules.length} règles
          </summary>
          <pre className="management-result">{JSON.stringify(p, null, 2)}</pre>
          <p>Modifiez cette portée depuis « Mes filtres ».</p>
          <Button
            variant="outline"
            onClick={() => {
              const mailboxes = { ...value.mailboxes };
              delete mailboxes[scope];
              onChange({ ...value, mailboxes });
            }}
          >
            Rétablir l’héritage
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
      <h3>Exporter ou importer les réglages</h3>
      <p>
        Configuration de messagerie sans les clés secrètes. L’import prépare un
        brouillon soumis à validation avant application.
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
          Exporter
        </Button>
        <label className="configuration-import">
          <Upload size={16} />
          Importer un fichier JSON
          <input
            type="file"
            accept="application/json,.json"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              try {
                if (file.size > 128 * 1024)
                  throw new Error('Maximum : 128 Kio.');
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
                  throw new Error('Export NoiseFence récent requis.');
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
      <h3>Clés Spamhaus DQS et Scaleway</h3>
      <p>
        Stockage privé côté serveur. Les clés ne sont jamais relues dans le
        navigateur, exportées ou enregistrées dans l’historique. CRDF et
        VirusTotal se configurent dans « Protection avancée ».
      </p>
      <div className="management-grid">
        <label>
          Fournisseur
          <select
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setKey('');
              setNotice('');
            }}
          >
            <option value="spamhaus">
              Spamhaus DQS · {keys.spamhaus ? 'configuré' : 'à connecter'}
            </option>
            {keys.scaleway_available && (
              <option value="scaleway">
                Scaleway · {keys.scaleway ? 'configuré' : 'à connecter'}
              </option>
            )}
          </select>
        </label>
        <label>
          Nouvelle clé
          <input
            type="password"
            autoComplete="new-password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
      </div>
      <p>
        Une clé Spamhaus autorisée est nécessaire. Enregistrer la clé conserve
        l’activation actuelle du connecteur ; son interrupteur se trouve dans
        les moteurs de détection.
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
                ? 'Clé enregistrée. Configuration rechargée pour les prochaines analyses.'
                : (result.message ?? 'Clé enregistrée.'),
            );
            await onSaved();
          } catch (e) {
            setError((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? 'Enregistrement…' : 'Enregistrer la clé'}
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
