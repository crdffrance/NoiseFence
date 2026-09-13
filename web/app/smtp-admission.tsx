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
  disabled: 'Désactivé',
  exempt: 'Exception',
  not_selected: 'Aucun report nécessaire',
  first_seen: 'Première tentative différée',
  too_soon: 'Nouvelle tentative trop tôt',
  retry_passed: 'Nouvelle tentative acceptée',
  passed: 'Passage mémorisé',
  rate_limited: 'Débit dépassé',
  capacity: 'État saturé · passage autorisé',
  unavailable: 'État indisponible · passage autorisé',
  clock_skew: 'Horloge incohérente · passage autorisé',
};
const reasons: Record<string, string> = {
  ip_reputation: 'Réputation IP défavorable',
  invalid_helo: 'HELO sans domaine ni adresse IP valide',
  sender_rate_exceeded: 'Limite de débit atteinte',
  delivery_notification_or_postmaster: 'Avis de livraison ou postmaster',
};
export function AdmissionDetails({
  reports,
}: {
  reports: AdmissionDecision[];
}) {
  return (
    <section aria-label="Admission SMTP">
      <h3>Admission SMTP avant réception</h3>
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
        Ces contrôles de transport n’ajoutent aucun point au score antispam.
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
  const [networks, setNetworks] = useState(value.allow_networks.join('\n'));
  useEffect(
    () => setNetworks(value.allow_networks.join('\n')),
    [value.allow_networks],
  );
  const [error, setError] = useState('');
  useEffect(() => {
    api<{
      counts: { mode: string; status: string; count: number }[];
      shared: boolean;
    }>('/admin/admission')
      .then(setReport)
      .catch(() => setError('Statistiques temporairement indisponibles.'));
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
        <h2>Greylisting et protection du transport</h2>
        <p>
          Demande aux expéditeurs suspects de réessayer avant de recevoir le
          corps. Le délai est partagé entre les MX ; un échec de coordination
          laisse passer la tentative.
        </p>
        <label>
          <input
            type="checkbox"
            checked={value.enabled}
            onChange={(e) => set('enabled', e.target.checked)}
          />{' '}
          Activer les contrôles d’admission SMTP
        </label>
        <label className="field">
          <span>Mode du transport</span>
          <select
            value={value.mode}
            onChange={(e) =>
              set('mode', e.target.value as AdmissionSettings['mode'])
            }
          >
            <option value="observe">Observer sans retarder</option>
            <option value="enforce">
              Appliquer les reports temporaires (451)
            </option>
          </select>
          <small>
            Indépendant de l’observation du contenu. L’application peut retarder
            des messages légitimes ; elle ne les classe pas Spam.
          </small>
        </label>
        <label>
          <input
            type="checkbox"
            checked={value.greylisting}
            onChange={(e) => set('greylisting', e.target.checked)}
          />{' '}
          Greylisting sélectif
        </label>
        <div className="form-grid">
          {number(
            'minimum_providers',
            'Signaux concordants requis',
            2,
            8,
            'Au moins une liste IP positive ; les opérateurs distincts et un HELO invalide sont comptés.',
          )}
          {number(
            'retry_delay_seconds',
            'Délai minimum (secondes)',
            1,
            3600,
            'Les essais précoces ne repoussent pas ce délai.',
          )}
          {number(
            'retry_max_age_seconds',
            'Expiration sans nouvel essai (secondes)',
            2,
            604800,
            'Doit dépasser le délai minimum.',
          )}
          {number(
            'retention_seconds',
            'Mémorisation après nouvel essai (secondes)',
            1,
            2592000,
            'Durée fixe, non prolongée par le trafic.',
          )}
        </div>
        <p className="muted">
          Regroupement des serveurs expéditeurs en /24 IPv4 et /64 IPv6, limité
          à l’exception de greylisting. Les avis à expéditeur nul et postmaster
          en sont exemptés. Leurs limites de débit restent applicables.
        </p>
      </div>
      <div className="management-card">
        <h3>Débit et ralentissement (teergrubing)</h3>
        <div className="form-grid">
          {number(
            'rate_per_minute',
            'Tentatives par IP et par minute',
            0,
            60000,
            '0 désactive le quota. Partagé entre les MX ; IPv6 regroupée en /64.',
          )}
          {number(
            'rate_burst',
            'Rafale autorisée',
            1,
            10000,
            'Nombre de tentatives disponibles immédiatement.',
          )}
          {number(
            'tarpit_delay_ms',
            'Attente avant réponse 451 (ms)',
            0,
            5000,
            '0 désactive le ralentissement. Réservé aux tentatives différées.',
          )}
          {number(
            'tarpit_session_budget_ms',
            'Attente maximale par connexion (ms)',
            0,
            10000,
            'Conservée après RSET et STARTTLS.',
          )}
          {number(
            'tarpit_max_concurrent',
            'Connexions ralenties simultanément par MX',
            1,
            64,
            'Une saturation supprime l’attente supplémentaire.',
          )}
          {number(
            'max_entries',
            'Capacité des états par mode',
            1,
            100000,
            'Les états de retry actifs ne sont jamais évincés.',
          )}
        </div>
      </div>
      <div className="management-card">
        <h3>Exceptions de confiance</h3>
        <label className="field">
          <span>Réseaux IP/CIDR, un par ligne</span>
          <textarea
            rows={4}
            value={networks}
            onChange={(e) => setNetworks(e.target.value)}
            onBlur={() =>
              set(
                'allow_networks',
                networks
                  .split('\n')
                  .map((v) => v.trim())
                  .filter(Boolean),
              )
            }
            placeholder={'192.0.2.10/32\n2001:db8::/64'}
          />
          <small>
            Exempte ces IP du greylisting et du quota. Aucun domaine ou
            expéditeur déclaré ne suffit à obtenir une exception.
          </small>
        </label>
      </div>
      <div className="management-card">
        <h3>Décisions des 30 derniers jours</h3>
        {error && <output>{error}</output>}
        {report && (
          <>
            <p>
              {report.shared ? 'État commun des MX' : 'État de ce serveur'} ·
              compteurs de tentatives, pas de messages uniques.
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
              <p className="muted">Aucune tentative observée pour le moment.</p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
