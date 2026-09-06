'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ShieldCheck,
  Search,
  LogOut,
  ArrowLeft,
  Check,
  Flag,
  Activity,
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
import { registerFeedbackTool } from './webmcp';
type User = {
  username: string;
  admin: boolean;
  csrf: string;
  addresses: string[];
};
type Mail = {
  id: string;
  created: number;
  sender: string;
  subject: string;
  score: number;
  tagged: boolean;
  complete: boolean;
  model: string;
  reasons: { id: string; detail: string; weight: number }[];
  recipients: { address: string; status: string }[];
  feedback: boolean | null;
  antivirus?: {
    status: 'disabled' | 'clean' | 'malware' | 'suspicious' | 'unscannable' | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  signatures?: {
    status: 'disabled' | 'clean' | 'malware' | 'suspicious' | 'unscannable' | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  llm?: {
    status: 'disabled' | 'not_needed' | 'busy' | 'budget_limited' | 'pricing_expired' | 'unavailable' | 'complete';
    model: string;
    prompt_version: string;
    elapsed_ms: number;
  };
  semantic?: {
    status: 'disabled' | 'complete' | 'busy' | 'unavailable';
    model: string;
    encoder: string;
    elapsed_ms: number;
  };
};
type Stats = {
  received: number;
  flagged: number;
  pending: number;
  mode: string;
  threshold: number;
};
async function api<T = unknown>(path: string, data?: unknown, csrf?: string) {
  const response = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin',
    method: data === undefined ? 'GET' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  if (!response.ok) {
    if (response.status === 401)
      window.dispatchEvent(new Event('session-expired'));
    const error = (await response.json().catch(() => ({}))) as {
      error?: string;
    };
    throw new Error(
      error.error ||
        (response.status === 401
          ? 'Connectez-vous pour continuer.'
          : 'La demande a échoué. Réessayez.'),
    );
  }
  return (await response.json()) as T;
}
export default function Home() {
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
      const [messages, totals] = await Promise.all([
        api<Mail[]>(
          `/messages?q=${encodeURIComponent(search)}&filter=${filter}&offset=${offset}`,
        ),
        api<Stats>('/stats'),
      ]);
      if (user !== activeUser.current || requestId !== latestRequest.current)
        return;
      setMails(messages);
      setStats(totals);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
  }, [user, search, filter, offset]);
  useEffect(() => {
    const timer = setTimeout(refresh, 200);
    return () => clearTimeout(timer);
  }, [refresh]);
  const recordFeedback = useCallback(
    async (id: string, spam: boolean) => {
      if (!user) throw new Error('Connexion requise.');
      await api(`/messages/${id}/feedback`, { spam }, user.csrf);
      setSelected((previous) =>
        previous?.id === id ? { ...previous, feedback: spam } : previous,
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
  async function feedback(spam: boolean) {
    if (!selected || !user) return;
    setBusy(true);
    try {
      await recordFeedback(selected.id, spam);
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
        <div className="rail-label">VOTRE ESPACE</div>
        <button className="nav-active" onClick={() => setSelected(null)}>
          <Activity size={18} /> Historique des messages
        </button>
        <div className="rail-footer">
          <strong>{user.username}</strong>
          <span>{user.addresses.join(', ') || 'Aucune adresse attribuée'}</span>
          <Button
            variant="ghost"
            onClick={async () => {
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
            Messagerie / {selected ? 'Décision du filtre' : 'Historique'}
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
                  {selected.score.toFixed(1)}
                  <span>/ 100</span>
                </div>
                <p className="muted">Indice de suspicion · {selected.model}</p>
                {selected.semantic && selected.semantic.status !== 'disabled' && (
                  <p className="muted">Analyse multilingue locale : {{
                    complete: 'effectuée',
                    busy: 'capacité occupée, analyse incomplète',
                    unavailable: 'indisponible ou délai dépassé',
                  }[selected.semantic.status]} · {selected.semantic.elapsed_ms} ms</p>
                )}
                {selected.llm && selected.llm.status !== 'disabled' && (
                  <p className="muted">Analyse complémentaire Scaleway : {{
                    not_needed: 'non sollicitée pour ce message',
                    busy: 'capacité occupée, analyse locale conservée',
                    budget_limited: 'plafond atteint, analyse locale conservée',
                    pricing_expired: 'tarifs à revalider, analyse locale conservée',
                    unavailable: 'indisponible',
                    complete: 'effectuée',
                  }[selected.llm.status]}{selected.llm.status === 'complete' && ` · ${selected.llm.model} · ${selected.llm.elapsed_ms} ms`}</p>
                )}
                {selected.antivirus && selected.antivirus.status !== 'disabled' && (
                  <div className="notice">
                    <strong>Antivirus : {{
                      clean: 'aucune détection',
                      malware: 'fichier malveillant détecté',
                      suspicious: 'signal suspect à examiner',
                      unscannable: 'analyse limitée ou contenu chiffré',
                      unavailable: 'service indisponible',
                    }[selected.antivirus.status]}</strong>
                    {selected.antivirus.signature && <p>{selected.antivirus.signature}</p>}
                    <small>ClamAV · {selected.antivirus.elapsed_ms} ms</small>
                  </div>
                )}
                {selected.signatures && selected.signatures.status !== 'disabled' && (
                  <p className="muted">Signatures complémentaires : {{
                    clean: 'aucune détection',
                    malware: 'signal consultatif à examiner',
                    suspicious: 'signal consultatif à examiner',
                    unscannable: 'analyse limitée',
                    unavailable: 'service indisponible',
                  }[selected.signatures.status]} · {selected.signatures.elapsed_ms} ms</p>
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
                      <code>
                        {r.weight > 0 ? '+' : ''}
                        {r.weight.toFixed(1)}
                      </code>
                    </li>
                  ))}
                </ul>
                {!selected.reasons.length && (
                  <p>Aucun signal de suspicion relevé.</p>
                )}
              </section>
              <section className="panel">
                <h2>Votre avis compte</h2>
                <p className="muted">
                  Corrigez la décision pour améliorer les prochains classements.
                </p>
                <div className="feedback-actions">
                  <Button
                    disabled={busy}
                    variant={
                      selected.feedback === false ? 'default' : 'outline'
                    }
                    onClick={() => feedback(false)}
                  >
                    <Check size={17} /> Légitime
                  </Button>
                  <Button
                    disabled={busy}
                    variant={selected.feedback === true ? 'default' : 'outline'}
                    onClick={() => feedback(true)}
                  >
                    <Flag size={17} /> Spam
                  </Button>
                </div>
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
                  Le corps et les pièces jointes sont supprimés après livraison.
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
                  Les décisions du filtre pour vos adresses, sur les 30 derniers
                  jours.
                </p>
              </div>
              <Button variant="outline" onClick={refresh}>
                Actualiser
              </Button>
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
                <strong>{stats?.flagged.toLocaleString('fr-FR') ?? '—'}</strong>
              </section>
              <section>
                <span>Livraisons en attente</span>
                <strong>{stats?.pending.toLocaleString('fr-FR') ?? '—'}</strong>
              </section>
            </div>
            <section className="messages">
              <div className="toolbar">
                <fieldset className="tabs" aria-label="Filtrer les messages">
                  {[
                    ['all', 'Tous'],
                    ['spam', 'Spam détecté'],
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
                    aria-label="Rechercher par objet ou expéditeur"
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
                    <TableHead>Classement</TableHead>
                    <TableHead>Score</TableHead>
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
                          <span>{m.sender || 'Notification de livraison'}</span>
                        </button>
                      </TableCell>
                      <TableCell>
                        <span className={`status ${m.tagged ? 'spam' : ''}`}>
                          {!m.complete
                            ? 'Incomplet'
                            : m.tagged
                              ? '[SPAM] ajouté'
                              : m.score >= (stats?.threshold ?? 95)
                                ? 'Suspect'
                                : 'Non marqué'}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="score">{m.score.toFixed(1)}</span>
                      </TableCell>
                      <TableCell className="muted">
                        {new Date(m.created * 1000).toLocaleString('fr-FR', {
                          day: '2-digit',
                          month: 'short',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
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
                      { current_password: password, new_password: newPassword },
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
      </main>
    </div>
  );
}
