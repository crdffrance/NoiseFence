'use client';
import { useState } from 'react';
import { Plus, Trash2, FlaskConical, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { actionLabel, type DeliveryAction } from './actions';
type Category = 'spam' | 'publicity' | 'legitimate' | 'undetermined';
type Field =
  | 'envelope_from'
  | 'from_domain'
  | 'header_from'
  | 'subject'
  | 'body'
  | 'recipient'
  | 'recipient_domain'
  | 'size'
  | 'score'
  | 'category'
  | 'signal'
  | 'dmarc';
type Operator =
  | 'equals'
  | 'contains'
  | 'starts_with'
  | 'ends_with'
  | 'present'
  | 'absent'
  | 'at_least'
  | 'at_most';
type Condition = { field: Field; op: Operator; value: string };
type Profile = {
  id: string;
  name: string;
  threshold: number | null;
  require_corroboration: boolean;
  spam: DeliveryAction;
  publicity: DeliveryAction;
  review: DeliveryAction;
  quarantine_days: number;
};
type Rule = {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  scope: string;
  expires: number | null;
  any: boolean;
  conditions: Condition[];
  category: Category | null;
  action: DeliveryAction | null;
  stop: boolean;
};
export type CustomPolicy = {
  profiles: Profile[];
  bindings: { scope: string; profile: string }[];
  rules: Rule[];
};
export type FilteringAssessment = {
  policy: string;
  profile: string | null;
  threshold: number;
  original_category: Category;
  category: Category;
  matched: { id: string; name: string; fields: Field[] }[];
  unavailable_conditions: number;
  action: {
    requested: DeliveryAction;
    effective: DeliveryAction;
    reason: string;
    quarantine_days: number;
  };
};
const empty: CustomPolicy = { profiles: [], bindings: [], rules: [] };
const fields: Record<Field, string> = {
  envelope_from: 'Expéditeur SMTP',
  from_domain: 'Domaine expéditeur SMTP',
  header_from: 'Adresse From',
  subject: 'Objet décodé',
  body: 'Texte MIME',
  recipient: 'Adresse destinataire',
  recipient_domain: 'Domaine destinataire',
  size: 'Taille en octets',
  score: 'Indice de suspicion',
  category: 'Classement initial',
  signal: 'Identifiant de signal',
  dmarc: 'Résultat DMARC',
};
const operators: Record<Operator, string> = {
  equals: 'Est égal à',
  contains: 'Contient',
  starts_with: 'Commence par',
  ends_with: 'Se termine par',
  present: 'Est présent',
  absent: 'Est absent',
  at_least: 'Au moins',
  at_most: 'Au plus',
};
const categories: Record<Category, string> = {
  spam: 'Spam',
  publicity: 'Publicité',
  legitimate: 'Légitime',
  undetermined: 'À examiner',
};
export function FilteringDetails({ value }: { value: FilteringAssessment }) {
  return (
    <div className="filter-assessment">
      <strong>
        {value.profile || 'Politique générale'} · {categories[value.category]}
      </strong>
      <p>
        {actionLabel[value.action.requested]} demandé ·{' '}
        {actionLabel[value.action.effective]} appliqué
        {value.action.reason === 'observation'
          ? ' (observation)'
          : value.action.reason === 'incomplete'
            ? ' (analyse incomplète)'
            : ''}
      </p>
      <p className="muted small">
        Classement initial : {categories[value.original_category]} · seuil{' '}
        {value.threshold} · politique {value.policy.slice(0, 12)}
      </p>
      {value.matched.length > 0 ? (
        <ul>
          {value.matched.map((r) => (
            <li key={r.id}>
              {r.name} · {r.fields.map((f) => fields[f]).join(', ')}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted small">Aucune règle personnalisée déclenchée.</p>
      )}
      {value.unavailable_conditions > 0 && (
        <p className="muted small">
          {value.unavailable_conditions} condition(s) sans donnée disponible.
        </p>
      )}
    </div>
  );
}
function ActionSelect({
  label,
  value,
  onChange,
  review = false,
}: {
  label: string;
  value: DeliveryAction;
  onChange: (v: DeliveryAction) => void;
  review?: boolean;
}) {
  return (
    <label>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as DeliveryAction)}
      >
        {(['deliver', 'tag', 'quarantine'] as const)
          .filter((a) => !review || a !== 'tag')
          .map((a) => (
            <option key={a} value={a}>
              {actionLabel[a]}
            </option>
          ))}
      </select>
    </label>
  );
}
export function CustomFiltering({
  policy,
  onChange,
  domains,
  locked,
  csrf,
}: {
  policy: CustomPolicy | null | undefined;
  onChange: (p: CustomPolicy | null) => void;
  domains: string[];
  locked: boolean;
  csrf: string;
}) {
  const p = policy || empty;
  const [sim, setSim] = useState({
    recipient: '',
    sender: '',
    subject: '',
    body: '',
    score: 20,
  });
  const [result, setResult] = useState<FilteringAssessment | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function updateProfile(index: number, patch: Partial<Profile>) {
    onChange({
      ...p,
      profiles: p.profiles.map((v, i) =>
        i === index ? { ...v, ...patch } : v,
      ),
    });
  }
  function updateRule(index: number, patch: Partial<Rule>) {
    onChange({
      ...p,
      rules: p.rules.map((v, i) => (i === index ? { ...v, ...patch } : v)),
    });
  }
  return (
    <div className="custom-filtering">
      <div className="panel">
        <div className="section-heading">
          <SlidersHorizontal size={20} />
          <h2>Une politique adaptée à chaque destinataire</h2>
        </div>
        <p className="muted">
          L’adresse exacte prime sur le domaine, puis sur l’organisation. Les
          alias sont pris en compte. Les contrôles techniques s’exécutent une
          seule fois par message.
        </p>
        <p className="small">
          Le mode observation transmet toujours. Les préfixes nécessitent les
          validations Proton. Les règles ne désactivent pas la priorité de
          l’antivirus.
        </p>
        <datalist id="filter-scopes">
          <option value="*">Toute l’organisation</option>
          {domains.map((d) => (
            <option key={d} value={`*@${d}`}>
              {d}
            </option>
          ))}
        </datalist>
      </div>
      <div className="section-heading">
        <h2>Profils de sensibilité</h2>
        <Button
          disabled={p.profiles.length >= 32}
          onClick={() =>
            onChange({
              ...p,
              profiles: [
                ...p.profiles,
                {
                  id: crypto.randomUUID(),
                  name: 'Nouveau profil',
                  threshold: null,
                  require_corroboration: true,
                  spam: 'quarantine',
                  publicity: 'deliver',
                  review: 'deliver',
                  quarantine_days: 14,
                },
              ],
            })
          }
        >
          <Plus size={16} /> Ajouter un profil
        </Button>
      </div>
      {p.profiles.length === 0 && (
        <p className="empty-state">
          Tous les destinataires héritent actuellement de la politique générale.
        </p>
      )}
      {p.profiles.map((profile, i) => (
        <div className="panel custom-card" key={profile.id}>
          <div className="custom-grid">
            <label htmlFor={`custom-filtering-1-${i}`}>
              Nom du profil
              <Input
                id={`custom-filtering-1-${i}`}
                value={profile.name}
                maxLength={100}
                onChange={(e) => updateProfile(i, { name: e.target.value })}
              />
            </label>
            <label>
              Sensibilité
              <select
                disabled={locked}
                value={
                  profile.threshold === null
                    ? 'inherit'
                    : profile.threshold === 98
                      ? 'prudent'
                      : profile.threshold === 95
                        ? 'balanced'
                        : profile.threshold === 90
                          ? 'strict'
                          : 'custom'
                }
                onChange={(e) =>
                  updateProfile(i, {
                    threshold: {
                      inherit: null,
                      prudent: 98,
                      balanced: 95,
                      strict: 90,
                      custom: profile.threshold || 95,
                    }[e.target.value as 'inherit'],
                  })
                }
              >
                <option value="inherit">Hériter du moteur calibré</option>
                <option value="prudent">Prudent · seuil 98</option>
                <option value="balanced">Équilibré · seuil 95</option>
                <option value="strict">Strict · seuil 90</option>
                <option value="custom">Seuil personnalisé</option>
              </select>
            </label>
            {profile.threshold !== null && (
              <label htmlFor={`custom-filtering-2-${i}`}>
                Seuil
                <Input
                  id={`custom-filtering-2-${i}`}
                  type="number"
                  min={50}
                  max={100}
                  step={0.1}
                  disabled={locked}
                  value={profile.threshold}
                  onChange={(e) =>
                    updateProfile(i, { threshold: Number(e.target.value) })
                  }
                />
              </label>
            )}
            <label htmlFor={`custom-filtering-3-${i}`}>
              Quarantaine (jours)
              <Input
                id={`custom-filtering-3-${i}`}
                type="number"
                min={1}
                max={30}
                value={profile.quarantine_days}
                onChange={(e) =>
                  updateProfile(i, { quarantine_days: Number(e.target.value) })
                }
              />
            </label>
            <ActionSelect
              label="Spam"
              value={profile.spam}
              onChange={(spam) => updateProfile(i, { spam })}
            />
            <ActionSelect
              label="Publicité"
              value={profile.publicity}
              onChange={(publicity) => updateProfile(i, { publicity })}
            />
            <ActionSelect
              label="À examiner"
              value={profile.review}
              review
              onChange={(review) => updateProfile(i, { review })}
            />
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={profile.require_corroboration}
              onChange={(e) =>
                updateProfile(i, { require_corroboration: e.target.checked })
              }
            />{' '}
            Exiger plusieurs preuves concordantes
          </label>
          {locked && (
            <p className="muted small">
              Le seuil hérité est verrouillé par la calibration du modèle actif.
            </p>
          )}
          <Button
            variant="outline"
            onClick={() =>
              onChange({
                ...p,
                profiles: p.profiles.filter((_, n) => n !== i),
                bindings: p.bindings.filter((b) => b.profile !== profile.id),
              })
            }
          >
            <Trash2 size={15} /> Supprimer ce profil et ses affectations
          </Button>
        </div>
      ))}
      <div className="section-heading">
        <h2>Affectations</h2>
        <Button
          disabled={!p.profiles.length || p.bindings.length >= 1000}
          onClick={() =>
            onChange({
              ...p,
              bindings: [
                ...p.bindings,
                { scope: '*', profile: p.profiles[0].id },
              ],
            })
          }
        >
          <Plus size={16} /> Affecter un profil
        </Button>
      </div>
      <p className="muted small">
        Utilisez * pour l’organisation, *@domaine.fr pour un domaine, ou une
        adresse complète.
      </p>
      {p.bindings.map((b, i) => (
        <div className="custom-row" key={i}>
          <Input
            aria-label="Portée du profil"
            list="filter-scopes"
            value={b.scope}
            onChange={(e) =>
              onChange({
                ...p,
                bindings: p.bindings.map((v, n) =>
                  n === i ? { ...v, scope: e.target.value.toLowerCase() } : v,
                ),
              })
            }
          />
          <select
            aria-label="Profil affecté"
            value={b.profile}
            onChange={(e) =>
              onChange({
                ...p,
                bindings: p.bindings.map((v, n) =>
                  n === i ? { ...v, profile: e.target.value } : v,
                ),
              })
            }
          >
            {p.profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            aria-label="Supprimer cette affectation"
            onClick={() =>
              onChange({ ...p, bindings: p.bindings.filter((_, n) => n !== i) })
            }
          >
            <Trash2 size={16} />
          </Button>
        </div>
      ))}
      <div className="section-heading">
        <h2>Règles personnalisées</h2>
        <Button
          disabled={p.rules.length >= 100}
          onClick={() =>
            onChange({
              ...p,
              rules: [
                ...p.rules,
                {
                  id: crypto.randomUUID(),
                  name: 'Nouvelle règle',
                  enabled: true,
                  priority: (p.rules.length + 1) * 10,
                  scope: '*',
                  expires: null,
                  any: false,
                  conditions: [{ field: 'subject', op: 'contains', value: '' }],
                  category: 'publicity',
                  action: null,
                  stop: true,
                },
              ],
            })
          }
        >
          <Plus size={16} /> Ajouter une règle
        </Button>
      </div>
      <p className="muted small">
        Priorité croissante. Une règle ultérieure peut remplacer l’effet
        précédent, sauf si « Arrêter » est coché. Les valeurs textuelles
        ignorent la casse ; aucun lien n’est ouvert par la simulation.
      </p>
      {p.rules.map((rule, i) => (
        <div className="panel custom-card" key={rule.id}>
          <div className="custom-grid">
            <label htmlFor={`custom-filtering-4-${i}`}>
              Nom
              <Input
                id={`custom-filtering-4-${i}`}
                value={rule.name}
                maxLength={100}
                onChange={(e) => updateRule(i, { name: e.target.value })}
              />
            </label>
            <label htmlFor={`custom-filtering-5-${i}`}>
              Portée
              <Input
                id={`custom-filtering-5-${i}`}
                list="filter-scopes"
                value={rule.scope}
                onChange={(e) =>
                  updateRule(i, { scope: e.target.value.toLowerCase() })
                }
              />
            </label>
            <label htmlFor={`custom-filtering-6-${i}`}>
              Priorité
              <Input
                id={`custom-filtering-6-${i}`}
                type="number"
                min={0}
                max={65535}
                value={rule.priority}
                onChange={(e) =>
                  updateRule(i, { priority: Number(e.target.value) })
                }
              />
            </label>
            <label htmlFor={`custom-filtering-7-${i}`}>
              Expiration (UTC)
              <Input
                id={`custom-filtering-7-${i}`}
                type="datetime-local"
                value={
                  rule.expires
                    ? new Date(rule.expires * 1000).toISOString().slice(0, 16)
                    : ''
                }
                onChange={(e) =>
                  updateRule(i, {
                    expires: e.target.value
                      ? Math.floor(
                          new Date(`${e.target.value}Z`).getTime() / 1000,
                        )
                      : null,
                  })
                }
              />
            </label>
          </div>
          <div className="custom-row">
            <label className="check">
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(e) => updateRule(i, { enabled: e.target.checked })}
              />{' '}
              Active
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={rule.stop}
                onChange={(e) => updateRule(i, { stop: e.target.checked })}
              />{' '}
              Arrêter après correspondance
            </label>
            <label>
              Conditions
              <select
                value={rule.any ? 'any' : 'all'}
                onChange={(e) =>
                  updateRule(i, { any: e.target.value === 'any' })
                }
              >
                <option value="all">Toutes (ET)</option>
                <option value="any">Au moins une (OU)</option>
              </select>
            </label>
          </div>
          {rule.conditions.map((c, j) => (
            <div className="custom-row condition-row" key={j}>
              <select
                aria-label="Champ"
                value={c.field}
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, field: e.target.value as Field } : v,
                    ),
                  })
                }
              >
                {Object.entries(fields).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
              <select
                aria-label="Opérateur"
                value={c.op}
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, op: e.target.value as Operator } : v,
                    ),
                  })
                }
              >
                {Object.entries(operators).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
              <Input
                aria-label="Valeur"
                disabled={c.op === 'present' || c.op === 'absent'}
                value={c.value}
                maxLength={256}
                placeholder={
                  c.field === 'category'
                    ? 'spam, publicity, legitimate, undetermined'
                    : ''
                }
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, value: e.target.value } : v,
                    ),
                  })
                }
              />
              <Button
                variant="outline"
                aria-label="Supprimer cette condition"
                disabled={rule.conditions.length === 1}
                onClick={() =>
                  updateRule(i, {
                    conditions: rule.conditions.filter((_, n) => n !== j),
                  })
                }
              >
                <Trash2 size={15} />
              </Button>
            </div>
          ))}
          <Button
            variant="outline"
            disabled={rule.conditions.length >= 8}
            onClick={() =>
              updateRule(i, {
                conditions: [
                  ...rule.conditions,
                  { field: 'from_domain', op: 'equals', value: '' },
                ],
              })
            }
          >
            Ajouter une condition
          </Button>
          <div className="custom-grid">
            <label>
              Classer comme
              <select
                value={rule.category || ''}
                onChange={(e) =>
                  updateRule(i, {
                    category: (e.target.value || null) as Category | null,
                  })
                }
              >
                <option value="">Conserver le classement</option>
                {Object.entries(categories).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Action
              <select
                value={rule.action || ''}
                onChange={(e) =>
                  updateRule(i, {
                    action: (e.target.value || null) as DeliveryAction | null,
                  })
                }
              >
                <option value="">Hériter du profil</option>
                {(['deliver', 'tag', 'quarantine'] as const).map((a) => (
                  <option key={a} value={a}>
                    {actionLabel[a]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Button
            variant="outline"
            onClick={() =>
              onChange({ ...p, rules: p.rules.filter((_, n) => n !== i) })
            }
          >
            <Trash2 size={15} /> Supprimer la règle
          </Button>
        </div>
      ))}
      <form
        className="panel custom-card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError('');
          setResult(null);
          try {
            const data = await api<{ assessment: FilteringAssessment }>(
              '/admin/filtering/preview',
              { ...sim, policy: p },
              csrf,
            );
            setResult(data.assessment);
          } catch (err) {
            setError((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="section-heading">
          <FlaskConical size={20} />
          <h2>Simuler le brouillon</h2>
        </div>
        <p className="muted small">
          Aucun message envoyé ni réglage enregistré. Les contrôles DNS,
          antivirus et réputation restent inconnus. Cette simulation vérifie les
          conditions saisies, pas la précision du moteur.
        </p>
        <div className="custom-grid">
          <label htmlFor="custom-filtering-8">
            Destinataire
            <Input
              id="custom-filtering-8"
              required
              value={sim.recipient}
              onChange={(e) => setSim({ ...sim, recipient: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-9">
            Expéditeur SMTP
            <Input
              id="custom-filtering-9"
              value={sim.sender}
              onChange={(e) => setSim({ ...sim, sender: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-10">
            Objet
            <Input
              id="custom-filtering-10"
              value={sim.subject}
              onChange={(e) => setSim({ ...sim, subject: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-11">
            Indice simulé
            <Input
              id="custom-filtering-11"
              type="number"
              min={0}
              max={100}
              value={sim.score}
              onChange={(e) =>
                setSim({ ...sim, score: Number(e.target.value) })
              }
            />
          </label>
        </div>
        <label>
          Texte
          <textarea
            rows={3}
            value={sim.body}
            maxLength={100000}
            onChange={(e) => setSim({ ...sim, body: e.target.value })}
          />
        </label>
        <Button type="submit" disabled={busy}>
          {busy ? 'Simulation…' : 'Tester les règles'}
        </Button>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {result && <FilteringDetails value={result} />}
      </form>
    </div>
  );
}
