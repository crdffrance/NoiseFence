'use client';
import { useEffect, useState } from 'react';
import { Plus, Trash2, Save, RotateCcw, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api, type User } from './client';
import type { Preferences, Preference } from './management';
import type { CustomPolicy, Profile } from './custom-filtering';
type Rule = CustomPolicy['rules'][number];
type View = {
  defaults: Record<string, Profile>;
  revision: number;
  settings: Preferences;
  scopes: string[];
  mode: string;
  sensitivity_locked: boolean;
};
const fields: Record<Rule['conditions'][number]['field'], string> = {
  envelope_from: 'Expéditeur SMTP',
  from_domain: 'Domaine expéditeur',
  header_from: 'Adresse From',
  subject: 'Objet',
  body: 'Texte du message',
  recipient: 'Destinataire',
  recipient_domain: 'Domaine destinataire',
  size: 'Taille (octets)',
  score: 'Score',
  category: 'Catégorie',
  signal: 'Signal du moteur',
  dmarc: 'DMARC',
};
const ops: Record<Rule['conditions'][number]['op'], string> = {
  equals: 'Égal à',
  contains: 'Contient',
  starts_with: 'Commence par',
  ends_with: 'Se termine par',
  present: 'Présent',
  absent: 'Absent',
  at_least: 'Au moins',
  at_most: 'Au plus',
};
const actions = {
  deliver: 'Transmettre',
  tag: 'Marquer [SPAM] / [PUB]',
  quarantine: 'Quarantaine',
};
export function MyFilters({
  user,
  onDirty,
}: {
  user: User;
  onDirty: (dirty: boolean) => void;
}) {
  const [view, setView] = useState<View | null>(null);
  const [scope, setScope] = useState('');
  const [draft, setDraft] = useState<Preference>({ profile: null, rules: [] });
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const saved = view?.settings.mailboxes[scope] ?? { profile: null, rules: [] };
  const dirty = !!view && JSON.stringify(saved) !== JSON.stringify(draft);
  useEffect(() => {
    let active = true;
    api<View>('/preferences')
      .then((v) => {
        if (active) {
          setView(v);
          const s = v.scopes[0] ?? '';
          setScope(s);
          setDraft(v.settings.mailboxes[s] ?? { profile: null, rules: [] });
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [user.username]);
  useEffect(() => {
    onDirty(dirty);
    const leave = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener('beforeunload', leave);
    return () => window.removeEventListener('beforeunload', leave);
  }, [dirty, onDirty]);
  function choose(s: string) {
    if (
      dirty &&
      !window.confirm('Abandonner les modifications non enregistrées ?')
    )
      return;
    setScope(s);
    setDraft(view?.settings.mailboxes[s] ?? { profile: null, rules: [] });
    setNotice('');
  }
  async function save(reset = false) {
    if (!view) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api(
        '/preferences',
        { revision: view.revision, scope, preference: reset ? null : draft },
        user.csrf,
      );
      const next = await api<View>('/preferences');
      setView(next);
      setDraft(next.settings.mailboxes[scope] ?? { profile: null, rules: [] });
      setNotice('Préférences enregistrées pour les prochains messages.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function rule(i: number, p: Partial<Rule>) {
    setDraft({
      ...draft,
      rules: draft.rules.map((r, n) => (n === i ? { ...r, ...p } : r)),
    });
  }
  return (
    <div className="management-settings personal-filters">
      <div className="page-title">
        <p className="eyebrow">ESPACE PERSONNEL</p>
        <h1>
          <SlidersHorizontal size={26} /> Mes filtres
        </h1>
        <p>
          Choisissez la sensibilité et les actions pour vos adresses, puis
          affinez avec vos règles.
        </p>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}{' '}
          <Button
            variant="ghost"
            onClick={async () => {
              if (
                dirty &&
                !window.confirm('Recharger et abandonner le brouillon ?')
              )
                return;
              try {
                const v = await api<View>('/preferences');
                setView(v);
                setDraft(
                  v.settings.mailboxes[scope] ?? { profile: null, rules: [] },
                );
                setError('');
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            Recharger
          </Button>
        </p>
      )}
      {notice && <output className="notice">{notice}</output>}
      {!view ? (
        <p>Chargement des préférences…</p>
      ) : (
        <>
          <section className="management-card">
            <label>
              Adresse ou domaine autorisé
              <select
                value={view.scopes.includes(scope) ? scope : ''}
                onChange={(e) => choose(e.target.value)}
              >
                <option value="" disabled>
                  Choisir une portée
                </option>
                {view.scopes.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            {view.scopes.some((s) => s.startsWith('*@')) && (
              <label>
                Ou une adresse précise de votre domaine
                <input
                  aria-label="Adresse précise"
                  key={scope}
                  defaultValue={scope.startsWith('*@') ? '' : scope}
                  placeholder="prenom@domaine.fr"
                  onBlur={(e) => {
                    if (e.target.value && e.target.value !== scope)
                      choose(
                        e.target.value.replace(
                          /@([^@]+)$/,
                          (_, domain: string) => '@' + domain.toLowerCase(),
                        ),
                      );
                  }}
                />
              </label>
            )}
            <p>
              Portée sélectionnée :{' '}
              <strong>{scope || 'Aucune adresse attribuée'}</strong>
            </p>
            <p>
              Une adresse précise prévaut sur les réglages du domaine. Les
              règles globales de l’administrateur et la protection antivirus
              restent prioritaires.
            </p>
            {view.mode === 'observe' && (
              <p className="notice">
                Observation active : les décisions sont visibles dans
                l’historique, tous les messages sont transmis sans marquage ni
                quarantaine.
              </p>
            )}
          </section>
          {!view.settings.enabled && (
            <p className="notice">
              La personnalisation est désactivée par l’administrateur.
            </p>
          )}
          <fieldset
            disabled={!view.settings.enabled || busy || !scope}
            className="personal-controls"
          >
            <section className="management-card">
              <label className="setting-toggle">
                <input
                  type="checkbox"
                  checked={draft.profile !== null}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      profile: e.target.checked
                        ? {
                            ...(view.defaults[scope] ??
                              view.defaults['*@' + scope.split('@').pop()] ??
                              view.defaults['*']),
                            id: 'personal',
                            name: 'Préférences personnelles',
                            threshold: null,
                            require_corroboration: true,
                          }
                        : null,
                    })
                  }
                />
                Personnaliser le niveau et les actions
              </label>
              {draft.profile && (
                <div className="management-grid">
                  <label>
                    Sensibilité
                    <select
                      disabled={view.sensitivity_locked}
                      value={draft.profile.threshold ?? 'inherit'}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            threshold:
                              e.target.value === 'inherit'
                                ? null
                                : Number(e.target.value),
                          },
                        })
                      }
                    >
                      <option value="inherit">
                        Hériter du seuil administrateur
                      </option>
                      {[
                        [99.5, 'Très tolérant'],
                        [98, 'Tolérant'],
                        [95, 'Équilibré'],
                        [90, 'Strict'],
                        [85, 'Très strict'],
                      ]
                        .filter(
                          ([n]) =>
                            Number(n) >= view.settings.minimum_threshold &&
                            Number(n) <= view.settings.maximum_threshold,
                        )
                        .map(([n, label]) => (
                          <option key={n} value={n}>
                            {label} · seuil {n}
                          </option>
                        ))}
                      {draft.profile.threshold !== null &&
                        ![99.5, 98, 95, 90, 85].includes(
                          draft.profile.threshold,
                        ) && (
                          <option value={draft.profile.threshold}>
                            Personnalisé · {draft.profile.threshold}
                          </option>
                        )}
                    </select>
                  </label>
                  <label>
                    Seuil précis ({view.settings.minimum_threshold}–
                    {view.settings.maximum_threshold})
                    <input
                      type="number"
                      step="0.1"
                      disabled={view.sensitivity_locked}
                      min={view.settings.minimum_threshold}
                      max={view.settings.maximum_threshold}
                      value={draft.profile.threshold ?? ''}
                      placeholder="Hériter"
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            threshold:
                              e.target.value === ''
                                ? null
                                : e.target.valueAsNumber,
                          },
                        })
                      }
                    />
                  </label>
                  {(['spam', 'publicity', 'review'] as const).map((k) => (
                    <label key={k}>
                      {k === 'spam'
                        ? 'Spam détecté'
                        : k === 'publicity'
                          ? 'Publicité / mailing'
                          : 'Message à vérifier'}
                      <select
                        value={draft.profile![k]}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            profile: { ...draft.profile!, [k]: e.target.value },
                          })
                        }
                      >
                        {view.settings.allowed_actions
                          .filter((a) => k !== 'review' || a !== 'tag')
                          .map((a) => (
                            <option key={a} value={a}>
                              {actions[a]}
                            </option>
                          ))}
                      </select>
                    </label>
                  ))}
                  <label>
                    Conservation en quarantaine (jours)
                    <input
                      type="number"
                      min={1}
                      max={30}
                      value={draft.profile.quarantine_days}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          profile: {
                            ...draft.profile!,
                            quarantine_days: e.target.valueAsNumber,
                          },
                        })
                      }
                    />
                  </label>
                </div>
              )}
            </section>
            <section className="management-card">
              <h2>
                Mes règles · {draft.rules.length}/{view.settings.max_rules}
              </h2>
              <p>
                Les règles s’appliquent dans cet ordre, puis les règles de
                l’administrateur. Les corrections ne changent pas les messages
                déjà livrés.
              </p>
              <Button
                variant="outline"
                disabled={draft.rules.length >= view.settings.max_rules}
                onClick={() =>
                  setDraft({
                    ...draft,
                    rules: [
                      ...draft.rules,
                      {
                        id: crypto.randomUUID(),
                        name: 'Nouvelle règle',
                        enabled: true,
                        priority: draft.rules.length,
                        scope,
                        expires: null,
                        any: false,
                        conditions: [
                          { field: 'subject', op: 'contains', value: '' },
                        ],
                        category: 'spam',
                        action: view.settings.allowed_actions[0],
                        stop: false,
                      },
                    ],
                  })
                }
              >
                <Plus size={16} />
                Ajouter une règle
              </Button>
            </section>
            {draft.rules.map((r, i) => (
              <section className="management-card" key={r.id}>
                <div className="management-toolbar">
                  <label className="setting-toggle">
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      onChange={(e) => rule(i, { enabled: e.target.checked })}
                    />
                    Règle {i + 1}
                  </label>
                  <input
                    aria-label={`Nom de la règle ${i + 1}`}
                    value={r.name}
                    onChange={(e) => rule(i, { name: e.target.value })}
                  />
                  <Button
                    variant="ghost"
                    aria-label={`Supprimer la règle ${i + 1}`}
                    onClick={() =>
                      setDraft({
                        ...draft,
                        rules: draft.rules.filter((_, n) => n !== i),
                      })
                    }
                  >
                    <Trash2 size={16} />
                  </Button>
                </div>
                <div className="management-grid">
                  <label>
                    Correspondance
                    <select
                      value={r.any ? 'any' : 'all'}
                      onChange={(e) =>
                        rule(i, { any: e.target.value === 'any' })
                      }
                    >
                      <option value="all">Toutes les conditions</option>
                      <option value="any">Au moins une condition</option>
                    </select>
                  </label>
                  <label>
                    Ordre de priorité
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      value={r.priority}
                      onChange={(e) =>
                        rule(i, { priority: e.target.valueAsNumber })
                      }
                    />
                  </label>
                  <label>
                    Expiration facultative (UTC)
                    <input
                      type="date"
                      value={
                        r.expires
                          ? new Date(r.expires * 1000)
                              .toISOString()
                              .slice(0, 10)
                          : ''
                      }
                      onChange={(e) =>
                        rule(i, {
                          expires: e.target.value
                            ? Math.floor(
                                new Date(
                                  e.target.value + 'T23:59:59Z',
                                ).getTime() / 1000,
                              )
                            : null,
                        })
                      }
                    />
                  </label>
                </div>
                {r.conditions.map((c, j) => (
                  <div className="personal-condition" key={j}>
                    <label>
                      Champ
                      <select
                        value={c.field}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j
                                ? {
                                    ...v,
                                    field: e.target.value as typeof c.field,
                                  }
                                : v,
                            ),
                          })
                        }
                      >
                        {Object.entries(fields).map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Comparaison
                      <select
                        value={c.op}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j
                                ? { ...v, op: e.target.value as typeof c.op }
                                : v,
                            ),
                          })
                        }
                      >
                        {Object.entries(ops).map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Valeur
                      <input
                        disabled={c.op === 'present' || c.op === 'absent'}
                        maxLength={256}
                        value={c.value}
                        onChange={(e) =>
                          rule(i, {
                            conditions: r.conditions.map((v, n) =>
                              n === j ? { ...v, value: e.target.value } : v,
                            ),
                          })
                        }
                      />
                    </label>
                    <Button
                      aria-label={`Supprimer la condition ${j + 1}`}
                      disabled={r.conditions.length <= 1}
                      variant="ghost"
                      onClick={() =>
                        rule(i, {
                          conditions: r.conditions.filter((_, n) => n !== j),
                        })
                      }
                    >
                      <Trash2 size={16} />
                    </Button>
                  </div>
                ))}
                <Button
                  variant="outline"
                  disabled={r.conditions.length >= 8}
                  onClick={() =>
                    rule(i, {
                      conditions: [
                        ...r.conditions,
                        { field: 'subject', op: 'contains', value: '' },
                      ],
                    })
                  }
                >
                  Ajouter une condition
                </Button>
                <div className="management-grid">
                  <label>
                    Classement
                    <select
                      value={r.category ?? ''}
                      onChange={(e) =>
                        rule(i, {
                          category: (e.target.value ||
                            null) as Rule['category'],
                        })
                      }
                    >
                      <option value="">Conserver le classement</option>
                      <option value="spam">Spam</option>
                      <option value="publicity">Publicité</option>
                      <option value="legitimate">Légitime</option>
                      <option value="undetermined">À vérifier</option>
                    </select>
                  </label>
                  <label>
                    Action
                    <select
                      value={r.action ?? ''}
                      onChange={(e) =>
                        rule(i, {
                          action: (e.target.value || null) as Rule['action'],
                        })
                      }
                    >
                      <option value="">Conserver l’action</option>
                      {view.settings.allowed_actions.map((a) => (
                        <option key={a} value={a}>
                          {actions[a]}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              </section>
            ))}
            <div className="personal-save">
              <span>
                {dirty
                  ? 'Modifications non enregistrées'
                  : 'Préférences enregistrées'}
              </span>
              <Button
                variant="outline"
                disabled={!view.settings.mailboxes[scope]}
                onClick={() => {
                  if (
                    window.confirm(
                      'Supprimer ces préférences et hériter des réglages globaux ?',
                    )
                  )
                    void save(true);
                }}
              >
                <RotateCcw size={16} />
                Hériter
              </Button>
              <Button disabled={!dirty} onClick={() => void save()}>
                <Save size={16} />
                {busy ? 'Enregistrement…' : 'Enregistrer mes filtres'}
              </Button>
            </div>
          </fieldset>
        </>
      )}
    </div>
  );
}
