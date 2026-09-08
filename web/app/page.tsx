'use client';
import {
  MailingDetails,
  type MailingReport,
  type FeedbackCategory,
} from './mailing';
import { ProtectionDetails, type ProtectionReport } from './protection';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ShieldCheck,
  Search,
  LogOut,
  ArrowLeft,
  Check,
  Flag,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { api, type User } from './client';
import { AdminConsole, navigation, type Section } from './admin';
import { registerFeedbackTool } from './webmcp';
type Mail = {
  protection?: ProtectionReport;
  mailing?: MailingReport;
  category: FeedbackCategory | 'undetermined';
  pub_tagged: boolean;
  feedback_category: FeedbackCategory | null;
  id: string;
  created: number;
  sender: string;
  subject: string;
  score: number;
  tagged: boolean;
  complete: boolean;
  model: string;
  decision?: {
    source: 'legacy' | 'fusion';
    outcome: 'legitimate' | 'unwanted' | 'undetermined';
    score: number | null;
    model: string;
  };
  fusion?: {
    mode: 'observe' | 'decision';
    status:
      | 'disabled'
      | 'not_run'
      | 'complete'
      | 'unavailable'
      | 'unsupported_profile'
      | 'validation_expired';
    model: string;
    prediction: {
      probability: number;
      tag_eligible: boolean;
      profile_supported: boolean;
      above_threshold: boolean;
      contributions: { feature: string; contribution: number }[];
    } | null;
  };
  reasons: { id: string; detail: string; weight: number }[];
  recipients: { address: string; status: string }[];
  feedback: boolean | null;
  antivirus?: {
    status:
      | 'disabled'
      | 'clean'
      | 'malware'
      | 'suspicious'
      | 'unscannable'
      | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  signatures?: {
    status:
      | 'disabled'
      | 'clean'
      | 'malware'
      | 'suspicious'
      | 'unscannable'
      | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  llm?: {
    status:
      | 'disabled'
      | 'not_needed'
      | 'busy'
      | 'budget_limited'
      | 'pricing_expired'
      | 'unavailable'
      | 'complete';
    model: string;
    prompt_version: string;
    elapsed_ms: number;
  };
  smtp_policy?: {
    status: 'disabled' | 'complete' | 'busy' | 'unavailable';
    elapsed_ms: number;
    candidate_weight: number;
    applied_weight: number;
    scoring_enabled: boolean;
  };
  semantic?: {
    status: 'disabled' | 'complete' | 'busy' | 'unavailable';
    model: string;
    encoder: string;
    elapsed_ms: number;
  };
  vision?: {
    status: 'disabled' | 'complete' | 'limited' | 'unavailable' | 'busy';
    parts: number;
    pages: number;
    text_chars: number;
    qr_codes: number;
    other_codes: number;
    link_domains: number;
    elapsed_ms: number;
  };
};
type Stats = {
  received: number;
  flagged: number;
  publicity: number;
  pending: number;
  mode: string;
  threshold: number;
  decision_source?: 'legacy' | 'fusion';
};
function displayedScore(mail: Mail) {
  return mail.decision
    ? mail.decision.score
    : mail.complete
      ? mail.score
      : null;
}
function unwanted(mail: Mail, threshold: number) {
  return mail.decision
    ? mail.decision.outcome === 'unwanted'
    : mail.complete && mail.score >= threshold;
}
const fusionFamilies: Record<string, string> = {
  lexical: 'Contenu textuel',
  semantic: 'Sens du message',
  auth: 'Authentification',
  reputation: 'Réputation',
  smtp_policy: 'Cohérence SMTP et DNS',
  antivirus: 'Antivirus',
  signatures: 'Signatures complémentaires',
  llm: 'Analyse complémentaire',
};
function fusionReason(feature: string) {
  const family =
    fusionFamilies[feature.split('.')[0]] ?? 'Observations combinées';
  if (feature.includes('unavailable'))
    return `${family} : contrôle indisponible`;
  if (feature.includes('busy')) return `${family} : capacité occupée`;
  if (feature.includes('not_run')) return `${family} : contrôle non effectué`;
  if (feature.includes('disabled')) return `${family} : contrôle désactivé`;
  if (feature.includes('limited')) return `${family} : analyse limitée`;
  return family;
}
export default function Home() {
  const [section, setSection] = useState<Section>('messages');
  const [domain, setDomain] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [configDirty, setConfigDirty] = useState(false);
  const [user, setUser] = useState<User | null>(null),
    [ready, setReady] = useState(false),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState(''),
    [newPassword, setNewPassword] = useState('');
  const [search, setSearch] = useState(''),
    [filter, setFilter] = useState('all'),
    [offset, setOffset] = useState(0);
  const [mails, setMails] = useState<Mail[]>([]),
    [selected, setSelected] = useState<Mail | null>(null),
    [stats, setStats] = useState<Stats | null>(null),
    [notice, setNotice] = useState('');
  const activeUser = useRef<User | null>(null);
  const latestRequest = useRef(0);
  const changeSession = useCallback((next: User | null) => {
    activeUser.current = next;
    latestRequest.current += 1;
    setUser(next);
    setMails([]);
    setStats(null);
    setSelected(null);
    setNotice('');
    setPassword('');
    setNewPassword('');
    setSearch('');
    setFilter('all');
    setOffset(0);
    setSection('messages');
    setDomain('');
    setDomains([]);
    setConfigDirty(false);
  }, []);
  useEffect(() => {
    const expired = () => changeSession(null);
    window.addEventListener('session-expired', expired);
    return () => window.removeEventListener('session-expired', expired);
  }, [changeSession]);
  useEffect(() => {
    api<User>('/me')
      .then(changeSession)
      .catch(() => {})
      .finally(() => setReady(true));
  }, [changeSession]);
  const refresh = useCallback(async () => {
    if (!user || user !== activeUser.current) return;
    const requestId = ++latestRequest.current;
    try {
      const [messages, totals, scope] = await Promise.all([
        api<Mail[]>(
          `/messages?q=${encodeURIComponent(search)}&filter=${filter}&offset=${offset}&domain=${encodeURIComponent(domain)}`,
        ),
        api<Stats>(`/stats?domain=${encodeURIComponent(domain)}`),
        api<string[]>('/domains'),
      ]);
      if (user !== activeUser.current || requestId !== latestRequest.current)
        return;
      setMails(messages);
      setStats(totals);
      setDomains(scope);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
  }, [user, search, filter, offset, domain]);
  useEffect(() => {
    const timer = setTimeout(refresh, 200);
    return () => clearTimeout(timer);
  }, [refresh]);
  const recordFeedback = useCallback(
    async (id: string, category: FeedbackCategory) => {
      if (!user) throw new Error('Connexion requise.');
      await api(`/messages/${id}/feedback`, { category }, user.csrf);
      setSelected((previous) =>
        previous?.id === id
          ? {
              ...previous,
              feedback: category === 'spam',
              feedback_category: category,
            }
          : previous,
      );
      setNotice(
        'Correction enregistrée. Le message déjà livré dans Proton reste inchangé.',
      );
      await refresh();
    },
    [user, refresh],
  );
  useEffect(
    () => (user ? registerFeedbackTool(recordFeedback) : undefined),
    [user, recordFeedback],
  );
  async function feedback(category: FeedbackCategory) {
    if (!selected || !user) return;
    setBusy(true);
    try {
      await recordFeedback(selected.id, category);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!ready)
    return (
      <main className="login">
        <output>Connexion à la passerelle…</output>
      </main>
    );
  if (!user)
    return (
      <main className="login">
        <form
          className="login-card"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError('');
            try {
              changeSession(await api<User>('/login', { username, password }));
              setPassword('');
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <span className="brand-icon">
            <ShieldCheck size={28} />
          </span>
          <p className="eyebrow">NOISEFENCE</p>
          <h1>
            Vos messages,
            <br />
            en toute clarté.
          </h1>
          <p className="muted">
            Consultez les décisions du filtre et signalez les erreurs de
            classement.
          </p>
          <label htmlFor="username">Identifiant</label>
          <Input
            id="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            maxLength={100}
          />
          <label htmlFor="password">Mot de passe de la console</label>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            maxLength={128}
          />
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <Button className="login-submit" disabled={busy} type="submit">
            {busy ? 'Connexion…' : 'Se connecter'}
          </Button>
          <p className="small muted">
            Utilisez le compte créé par votre administrateur.
          </p>
        </form>
      </main>
    );
  return (
    <div className="shell">
      <aside className="rail">
        <div className="wordmark">
          <ShieldCheck size={23} /> NoiseFence
        </div>
        <div className="rail-label">
          {user.admin ? 'ADMINISTRATION' : 'VOTRE ESPACE'}
        </div>
        <nav className="navigation" aria-label="Navigation principale">
          {navigation
            .filter((n) => user.admin || n.id === 'messages')
            .map((n) => (
              <button
                key={n.id}
                className={`nav-item ${section === n.id ? 'nav-active' : ''}`}
                aria-current={section === n.id ? 'page' : undefined}
                onClick={() => {
                  setSection(n.id);
                  setSelected(null);
                  setNotice('');
                }}
              >
                <n.icon size={18} />
                {n.label}
              </button>
            ))}
        </nav>
        <div className="rail-footer">
          <strong>{user.username}</strong>
          <span>
            {user.admin
              ? 'Administrateur · Tous les domaines'
              : user.addresses.join(', ') || 'Aucune adresse attribuée'}
          </span>
          <Button
            variant="ghost"
            onClick={async () => {
              if (
                configDirty &&
                !window.confirm(
                  'Des réglages ne sont pas appliqués. Quitter et les abandonner ?',
                )
              )
                return;
              try {
                await api('/logout', {}, user.csrf);
                changeSession(null);
                setSelected(null);
                setMails([]);
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <LogOut size={16} /> Déconnexion
          </Button>
        </div>
      </aside>
      <main className="workspace">
        <header className="topline">
          <span>
            Console /{' '}
            {selected
              ? 'Décision du filtre'
              : navigation.find((n) => n.id === section)?.label}
          </span>
          <span className="mode">
            <i />
            {stats?.mode === 'tag' ? 'Marquage actif' : 'Observation'}
          </span>
        </header>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {notice && <output className="notice">{notice}</output>}
        {user.admin && (
          <div hidden={section === 'messages'}>
            <AdminConsole
              user={user}
              section={section}
              onDirty={setConfigDirty}
              onApplied={refresh}
              onDomain={(name) => {
                setDomain(name);
                setOffset(0);
                setSection('messages');
                setSelected(null);
              }}
            />
          </div>
        )}
        {section === 'messages' && (
          <>
            {selected ? (
              <>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setSelected(null);
                    setNotice('');
                  }}
                >
                  <ArrowLeft size={17} /> Retour aux messages
                </Button>
                <div className="detail-heading">
                  <p className="eyebrow">DÉCISION DU FILTRE</p>
                  <h1>{selected.subject || '(Sans objet)'}</h1>
                  <p className="muted">
                    {selected.sender || 'Expéditeur d’enveloppe vide'} ·{' '}
                    {new Date(selected.created * 1000).toLocaleString('fr-FR')}
                  </p>
                </div>
                <div className="detail-grid">
                  <section className="panel">
                    <h2>Pourquoi ce classement ?</h2>
                    <div className="score-large">
                      {displayedScore(selected)?.toFixed(1) ?? '—'}
                      <span>/ 100</span>
                    </div>
                    <p className="muted">
                      {selected.decision?.outcome === 'undetermined'
                        ? selected.complete
                          ? 'À vérifier · confirmation insuffisante'
                          : 'Décision indéterminée'
                        : selected.decision?.source === 'fusion'
                          ? 'Estimation calibrée'
                          : 'Indice de suspicion'}
                      {' · '}
                      {selected.decision?.model ?? selected.model}
                    </p>
                    {selected.fusion &&
                      selected.fusion.status !== 'disabled' && (
                        <div className="notice">
                          <strong>
                            {selected.fusion.mode === 'observe'
                              ? 'Fusion en observation'
                              : 'Décision commune'}
                          </strong>
                          <p>
                            {
                              {
                                not_run:
                                  'Contexte insuffisant pour combiner les détecteurs.',
                                complete: selected.fusion.prediction
                                  ?.tag_eligible
                                  ? `Estimation : ${((selected.fusion.prediction?.probability ?? 0) * 100).toFixed(1)} / 100.`
                                  : 'Contrôles incomplets : estimation inutilisable pour le marquage.',
                                unavailable:
                                  'Fusion indisponible pour ce message.',
                                unsupported_profile:
                                  'Cette combinaison de contrôles n’a pas encore été validée.',
                                validation_expired:
                                  'Validation du modèle expirée : aucun préfixe ajouté.',
                              }[selected.fusion.status]
                            }
                          </p>
                          {selected.fusion.mode === 'observe' && (
                            <p>
                              Résultat de recherche, sans effet sur le
                              classement.
                            </p>
                          )}
                          <small>{selected.fusion.model}</small>
                          {selected.fusion.status === 'complete' &&
                            selected.fusion.prediction?.tag_eligible && (
                              <ul className="reasons">
                                {selected.fusion.prediction.contributions
                                  .filter((c) => c.contribution !== 0)
                                  .map((c, i) => (
                                    <li key={`${c.feature}-${i}`}>
                                      <span>{fusionReason(c.feature)}</span>
                                      <small>
                                        {c.contribution > 0
                                          ? 'Augmente'
                                          : 'Réduit'}{' '}
                                        l’estimation
                                      </small>
                                    </li>
                                  ))}
                              </ul>
                            )}
                        </div>
                      )}
                    {selected.smtp_policy &&
                      selected.smtp_policy.status !== 'disabled' && (
                        <p className="muted">
                          Cohérence SMTP et DNS :{' '}
                          {
                            {
                              complete: 'contrôlée',
                              busy: 'capacité occupée, contrôle incomplet',
                              unavailable: 'indisponible ou délai dépassé',
                            }[selected.smtp_policy.status]
                          }{' '}
                          · {selected.smtp_policy.elapsed_ms} ms
                          {selected.smtp_policy.status === 'complete' &&
                            !selected.smtp_policy.scoring_enabled &&
                            ' · observation sans effet sur le score'}
                        </p>
                      )}
                    {selected.semantic &&
                      selected.semantic.status !== 'disabled' && (
                        <p className="muted">
                          Analyse multilingue locale :{' '}
                          {
                            {
                              complete: 'effectuée',
                              busy: 'capacité occupée, analyse incomplète',
                              unavailable: 'indisponible ou délai dépassé',
                            }[selected.semantic.status]
                          }{' '}
                          · {selected.semantic.elapsed_ms} ms
                        </p>
                      )}
                    {selected.vision &&
                      selected.vision.status !== 'disabled' && (
                        <div className="notice">
                          <strong>
                            Lecture des images et PDF :{' '}
                            {
                              {
                                complete: selected.vision.parts
                                  ? 'effectuée'
                                  : 'aucun contenu visuel local',
                                limited:
                                  'partielle, limites atteintes ou document illisible',
                                busy: 'capacité occupée, analyse incomplète',
                                unavailable: 'indisponible ou délai dépassé',
                              }[selected.vision.status]
                            }
                          </strong>
                          {selected.vision.pages > 0 && (
                            <p>
                              {selected.vision.pages} page(s) ·{' '}
                              {selected.vision.text_chars} caractères ·{' '}
                              {selected.vision.qr_codes} QR code(s) ·{' '}
                              {selected.vision.other_codes} autre(s) code(s) ·{' '}
                              {selected.vision.link_domains} domaine(s) dans les
                              liens
                            </p>
                          )}
                          <small>
                            Traitement local · {selected.vision.elapsed_ms} ms ·
                            Les liens décodés ne sont pas ouverts.
                          </small>
                        </div>
                      )}
                    {selected.llm && selected.llm.status !== 'disabled' && (
                      <p className="muted">
                        Analyse complémentaire Scaleway :{' '}
                        {
                          {
                            not_needed: 'non sollicitée pour ce message',
                            busy: 'capacité occupée, analyse incomplète',
                            budget_limited:
                              'plafond atteint, analyse locale conservée',
                            pricing_expired:
                              'tarifs à revalider, analyse locale conservée',
                            unavailable: 'indisponible',
                            complete: 'effectuée',
                          }[selected.llm.status]
                        }
                        {selected.llm.status === 'complete' &&
                          ` · ${selected.llm.model} · ${selected.llm.elapsed_ms} ms`}
                      </p>
                    )}
                    {selected.antivirus &&
                      selected.antivirus.status !== 'disabled' && (
                        <div className="notice">
                          <strong>
                            Antivirus :{' '}
                            {
                              {
                                clean: 'aucune détection',
                                malware: 'fichier malveillant détecté',
                                suspicious: 'signal suspect à examiner',
                                unscannable:
                                  'analyse limitée ou contenu chiffré',
                                unavailable: 'service indisponible',
                              }[selected.antivirus.status]
                            }
                          </strong>
                          {selected.antivirus.signature && (
                            <p>{selected.antivirus.signature}</p>
                          )}
                          <small>
                            ClamAV · {selected.antivirus.elapsed_ms} ms
                          </small>
                        </div>
                      )}
                    {selected.signatures &&
                      selected.signatures.status !== 'disabled' && (
                        <p className="muted">
                          Signatures complémentaires :{' '}
                          {
                            {
                              clean: 'aucune détection',
                              malware: 'signal consultatif à examiner',
                              suspicious: 'signal consultatif à examiner',
                              unscannable: 'analyse limitée',
                              unavailable: 'service indisponible',
                            }[selected.signatures.status]
                          }{' '}
                          · {selected.signatures.elapsed_ms} ms
                        </p>
                      )}
                    {!selected.complete && (
                      <p className="notice">
                        Analyse incomplète : aucun préfixe ajouté.
                      </p>
                    )}
                    <ul className="reasons">
                      {selected.reasons.map((r, i) => (
                        <li key={`${r.id}-${i}`}>
                          <span>{r.detail}</span>
                          {selected.decision?.source !== 'fusion' && (
                            <code>
                              {r.weight > 0 ? '+' : ''}
                              {r.weight.toFixed(1)}
                            </code>
                          )}
                        </li>
                      ))}
                    </ul>
                    {!selected.reasons.length && (
                      <p>
                        {selected.fusion?.status === 'complete'
                          ? 'Aucun autre signal enregistré.'
                          : 'Aucun signal de suspicion relevé.'}
                      </p>
                    )}
                  </section>
                  {selected.mailing && (
                    <MailingDetails
                      report={selected.mailing}
                      category={selected.category}
                      tagged={selected.pub_tagged}
                    />
                  )}
                  {selected.protection && (
                    <ProtectionDetails report={selected.protection} />
                  )}
                  <section className="panel">
                    <h2>Votre avis compte</h2>
                    <p className="muted">
                      Corrigez la décision pour améliorer les prochains
                      classements.
                    </p>
                    <div className="feedback-actions">
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback_category === 'legitimate'
                            ? 'default'
                            : 'outline'
                        }
                        onClick={() => feedback('legitimate')}
                      >
                        <Check size={17} /> Légitime
                      </Button>
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback === true ? 'default' : 'outline'
                        }
                        onClick={() => feedback('spam')}
                      >
                        <Flag size={17} /> Spam
                      </Button>
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback_category === 'publicity'
                            ? 'default'
                            : 'outline'
                        }
                        onClick={() => feedback('publicity')}
                      >
                        PUB
                      </Button>
                    </div>
                    <p className="muted small">
                      PUB désigne une publicité ou une newsletter légitime. Une
                      publicité frauduleuse doit être signalée comme spam.
                    </p>
                    <h2 className="subheading">Livraison</h2>
                    {selected.recipients.map((r) => (
                      <p className="recipient" key={r.address}>
                        {r.address}
                        <span>
                          {(
                            {
                              pending: 'En attente',
                              sending: 'En cours',
                              delivered: 'Livré',
                              failed: 'Échec',
                              notified: 'Échec signalé',
                            } as Record<string, string>
                          )[r.status] || r.status}
                        </span>
                      </p>
                    ))}
                    <p className="small muted">
                      Le corps et les pièces jointes sont supprimés après
                      livraison.
                    </p>
                  </section>
                </div>
              </>
            ) : (
              <>
                <div className="page-heading">
                  <div>
                    <p className="eyebrow">VISIBILITÉ & CONTRÔLE</p>
                    <h1>Historique des messages</h1>
                    <p className="muted">
                      {domain
                        ? `Les messages de ${domain}`
                        : user.admin
                          ? 'Tous les domaines de votre organisation'
                          : 'Les messages de vos adresses'}{' '}
                      · 30 derniers jours.
                    </p>
                  </div>
                  <Button variant="outline" onClick={refresh}>
                    Actualiser
                  </Button>
                </div>
                <div className="scope-bar">
                  <label htmlFor="domain-scope">Périmètre</label>
                  <select
                    id="domain-scope"
                    value={domain}
                    onChange={(e) => {
                      setDomain(e.target.value);
                      setOffset(0);
                    }}
                  >
                    <option value="">
                      {user.admin ? 'Tous les domaines' : 'Tous mes accès'}
                    </option>
                    {domains.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                  <span className="small muted">
                    {user.admin
                      ? 'Visibilité complète des destinataires'
                      : 'Destinataires autorisés uniquement'}
                  </span>
                </div>
                <div className="stats">
                  <section>
                    <span>Messages reçus</span>
                    <strong>
                      {stats?.received.toLocaleString('fr-FR') ?? '—'}
                    </strong>
                  </section>
                  <section>
                    <span>Détectés comme spam</span>
                    <strong>
                      {stats?.flagged.toLocaleString('fr-FR') ?? '—'}
                    </strong>
                  </section>
                  <section>
                    <span>Publicités et newsletters</span>
                    <strong>
                      {stats?.publicity?.toLocaleString('fr-FR') ?? '—'}
                    </strong>
                  </section>
                  <section>
                    <span>Livraisons en attente</span>
                    <strong>
                      {stats?.pending.toLocaleString('fr-FR') ?? '—'}
                    </strong>
                  </section>
                </div>
                <section className="messages">
                  <div className="toolbar">
                    <fieldset
                      className="tabs"
                      aria-label="Filtrer les messages"
                    >
                      {[
                        ['all', 'Tous'],
                        ['spam', 'Spam détecté'],
                        ['publicity', 'PUB'],
                        ['legitimate', 'Légitime'],
                        ['pending', 'En attente'],
                        ['review', 'À vérifier'],
                        ['incomplete', 'Analyse incomplète'],
                      ].map(([value, label]) => (
                        <Button
                          key={value}
                          variant={filter === value ? 'default' : 'ghost'}
                          onClick={() => {
                            setFilter(value);
                            setOffset(0);
                          }}
                        >
                          {label}
                        </Button>
                      ))}
                    </fieldset>
                    <div className="search">
                      <Search size={18} />
                      <Input
                        aria-label="Rechercher par objet, expéditeur ou destinataire"
                        placeholder="Rechercher un message…"
                        value={search}
                        onChange={(e) => {
                          setSearch(e.target.value);
                          setOffset(0);
                        }}
                        maxLength={150}
                      />
                    </div>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Message</TableHead>
                        <TableHead>Destinataires</TableHead>
                        <TableHead>Classement</TableHead>
                        <TableHead>Score spam</TableHead>
                        <TableHead>Reçu le</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {mails.map((m) => (
                        <TableRow key={m.id}>
                          <TableCell>
                            <button
                              className="message-link"
                              onClick={() => {
                                setSelected(m);
                                setNotice('');
                              }}
                            >
                              <strong>{m.subject || '(Sans objet)'}</strong>
                              <span>
                                {m.sender || 'Notification de livraison'}
                              </span>
                            </button>
                          </TableCell>
                          <TableCell>
                            <span className="small recipient-list">
                              {m.recipients.map((r) => r.address).join(', ')}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className={`status ${unwanted(m, stats?.threshold ?? 95) ? 'spam' : m.category === 'publicity' ? 'publicity' : ''}`}
                            >
                              {!m.complete
                                ? 'Incomplet'
                                : m.tagged
                                  ? '[SPAM] ajouté'
                                  : unwanted(m, stats?.threshold ?? 95)
                                    ? 'Spam détecté'
                                    : m.pub_tagged
                                      ? '[PUB] ajouté'
                                      : m.category === 'publicity'
                                        ? 'PUB détecté'
                                        : m.category === 'undetermined'
                                          ? m.complete
                                            ? 'À vérifier'
                                            : 'Indéterminé'
                                          : 'Légitime'}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="score">
                              {displayedScore(m)?.toFixed(1) ?? '—'}
                            </span>
                          </TableCell>
                          <TableCell className="muted">
                            {new Date(m.created * 1000).toLocaleString(
                              'fr-FR',
                              {
                                day: '2-digit',
                                month: 'short',
                                hour: '2-digit',
                                minute: '2-digit',
                              },
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  {!mails.length && (
                    <div className="empty">
                      <ShieldCheck size={32} />
                      <h2>
                        {search
                          ? 'Aucun message correspondant'
                          : 'Aucun message pour le moment'}
                      </h2>
                      <p>
                        Les messages traités pour vos adresses apparaîtront ici.
                      </p>
                    </div>
                  )}
                  <div className="pagination">
                    <Button
                      variant="ghost"
                      disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - 50))}
                    >
                      Précédent
                    </Button>
                    <span>Page {Math.floor(offset / 50) + 1}</span>
                    <Button
                      variant="ghost"
                      disabled={mails.length < 50}
                      onClick={() => setOffset(offset + 50)}
                    >
                      Suivant
                    </Button>
                  </div>
                </section>
                <details className="account">
                  <summary>Changer mon mot de passe</summary>
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      try {
                        await api(
                          '/password',
                          {
                            current_password: password,
                            new_password: newPassword,
                          },
                          user.csrf,
                        );
                        setPassword('');
                        setNewPassword('');
                        changeSession(null);
                      } catch (e) {
                        setError((e as Error).message);
                      }
                    }}
                  >
                    <Input
                      type="password"
                      aria-label="Mot de passe actuel"
                      placeholder="Mot de passe actuel"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                    <Input
                      type="password"
                      aria-label="Nouveau mot de passe"
                      placeholder="Nouveau mot de passe (12 caractères minimum)"
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      minLength={12}
                      maxLength={128}
                      required
                    />
                    <Button type="submit">Enregistrer</Button>
                  </form>
                </details>
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}
