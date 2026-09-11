'use client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { UserPlus, Copy, Link as LinkIcon } from 'lucide-react';
import { api, type User } from './client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
type Invitation = {
  id: string;
  username: string;
  admin: boolean;
  addresses: string[];
  expires: number;
  version: number;
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
};
const statusNames = {
  pending: 'En attente',
  accepted: 'Activée',
  expired: 'Expirée',
  revoked: 'Révoquée',
};
export function Invitations({ user }: { user: User }) {
  const [items, setItems] = useState<Invitation[]>([]);
  const [epoch, setEpoch] = useState(0);
  const [form, setForm] = useState({
    username: '',
    addresses: '',
    admin: false,
    days: 3,
  });
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api<Invitation[]>('/admin/invitations')
      .then((v) => {
        if (active) setItems(v);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [epoch]);
  async function create(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setUrl('');
    setError('');
    setNotice('');
    try {
      const result = await api<{ url: string }>(
        '/admin/invitations',
        { ...form, addresses: form.addresses.split(/[\s,;]+/).filter(Boolean) },
        user.csrf,
      );
      setUrl(result.url);
      setEpoch((n) => n + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel invitation-panel">
      <div className="section-heading">
        <UserPlus size={20} />
        <h2>Inviter un utilisateur</h2>
      </div>
      <p className="muted">
        L’utilisateur choisit son mot de passe depuis un lien personnel. Le
        compte sera créé lors de son activation.
      </p>
      <form className="custom-card" onSubmit={create}>
        <div className="custom-grid">
          <label htmlFor="onboarding-1">
            Identifiant
            <Input
              id="onboarding-1"
              required
              maxLength={100}
              autoComplete="off"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
            />
          </label>
          <label>
            Expiration
            <select
              value={form.days}
              onChange={(e) =>
                setForm({ ...form, days: Number(e.target.value) })
              }
            >
              <option value={1}>24 heures</option>
              <option value={3}>3 jours</option>
              <option value={7}>7 jours</option>
            </select>
          </label>
          <label htmlFor="onboarding-2">
            Adresses ou domaines autorisés
            <Input
              id="onboarding-2"
              required={!form.admin}
              placeholder="alice@exemple.fr, *@exemple.fr"
              value={form.addresses}
              onChange={(e) => setForm({ ...form, addresses: e.target.value })}
            />
          </label>
          <label>
            Rôle
            <select
              value={form.admin ? 'admin' : 'user'}
              onChange={(e) =>
                setForm({ ...form, admin: e.target.value === 'admin' })
              }
            >
              <option value="user">Utilisateur · accès indiqués</option>
              <option value="admin">Administrateur · tous les domaines</option>
            </select>
          </label>
        </div>
        {form.admin && (
          <p className="small">
            Ce rôle permet de consulter tous les messages et de modifier les
            comptes et les réglages du serveur.
          </p>
        )}
        <Button type="submit" disabled={busy}>
          <LinkIcon size={16} />
          {busy ? 'Création…' : 'Créer le lien d’invitation'}
        </Button>
        <p className="muted small">
          Créer un nouveau lien pour le même identifiant révoque les liens
          précédents. Aucun email n’est envoyé automatiquement.
        </p>
      </form>
      {url && (
        <output className="invitation-result">
          <strong>Lien prêt à partager</strong>
          <p>
            Copiez-le maintenant : il ne sera plus affiché après avoir quitté
            cet écran.
          </p>
          <Input
            aria-label="Lien d’invitation personnel"
            readOnly
            value={url}
            onFocus={(e) => e.target.select()}
          />
          <Button
            variant="outline"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(url);
                setNotice('Lien copié.');
              } catch {
                setError('Sélectionnez le lien pour le copier manuellement.');
              }
            }}
          >
            <Copy size={16} /> Copier le lien
          </Button>
        </output>
      )}
      {notice && <output>{notice}</output>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="invitation-list">
        {items.map((item) => (
          <div className="invitation-item" key={item.id}>
            <div>
              <strong>{item.username}</strong>
              <p className="muted small">
                {item.admin ? 'Administrateur' : item.addresses.join(', ')} ·{' '}
                {statusNames[item.status]} · jusqu’au{' '}
                {new Date(item.expires * 1000).toLocaleString('fr-FR')}
              </p>
            </div>
            {item.status === 'pending' && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  setError('');
                  try {
                    await api(
                      '/admin/invitations/revoke',
                      { id: item.id, version: item.version },
                      user.csrf,
                    );
                    setUrl('');
                    setEpoch((n) => n + 1);
                  } catch (e) {
                    setError((e as Error).message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Révoquer
              </Button>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
export function OnboardingGate({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const captured = useRef(false);
  useEffect(() => {
    if (captured.current) return;
    captured.current = true;
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const value = hash.get('invite');
    if (value !== null) {
      window.history.replaceState(
        null,
        '',
        window.location.pathname + window.location.search,
      );
      queueMicrotask(() => setToken(value));
    } else queueMicrotask(() => setToken(null));
  }, []);
  if (token === undefined)
    return (
      <main className="onboarding-shell">
        <p>Chargement…</p>
      </main>
    );
  if (token !== null)
    return <AcceptInvitation token={token} onDone={() => setToken(null)} />;
  return children;
}
function AcceptInvitation({
  token,
  onDone,
}: {
  token: string;
  onDone: () => void;
}) {
  const [identity, setIdentity] = useState<{
    username: string;
    admin: boolean;
    addresses: string[];
  } | null>(null);
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api<typeof identity>('/onboarding/check', { token })
      .then((value) => {
        if (active) setIdentity(value);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [token]);
  return (
    <main className="onboarding-shell">
      <section className="panel onboarding-card">
        <div className="onboarding-icon">
          <UserPlus size={28} />
        </div>
        <span className="eyebrow">NOISEFENCE · VOTRE ACCÈS</span>
        <h1>
          {done ? 'Votre compte est prêt' : 'Bienvenue dans votre console'}
        </h1>
        {done ? (
          <>
            <p>
              Votre mot de passe est enregistré. Connectez-vous avec
              l’identifiant <strong>{identity?.username}</strong>.
            </p>
            <Button onClick={onDone}>Accéder à la connexion</Button>
          </>
        ) : identity ? (
          <>
            <p>
              Activez le compte <strong>{identity.username}</strong> pour
              consulter l’analyse de vos messages et signaler les erreurs de
              classement.
            </p>
            <div className="invitation-result">
              <strong>
                {identity.admin
                  ? 'Administrateur de la passerelle'
                  : 'Vos accès'}
              </strong>
              <p>
                {identity.admin
                  ? 'Tous les domaines, comptes et réglages de la passerelle.'
                  : identity.addresses.join(', ')}
              </p>
            </div>
            <form
              className="custom-card"
              onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                setError('');
                try {
                  await api('/onboarding/accept', {
                    token,
                    password,
                    confirmation,
                  });
                  setPassword('');
                  setConfirmation('');
                  setDone(true);
                } catch (err) {
                  setError((err as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <label htmlFor="onboarding-3">
                Choisir un mot de passe
                <Input
                  id="onboarding-3"
                  type="password"
                  required
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>
              <p className="muted small">
                12 à 128 octets. Une phrase de passe longue est recommandée.
              </p>
              <label htmlFor="onboarding-4">
                Confirmer le mot de passe
                <Input
                  id="onboarding-4"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={confirmation}
                  maxLength={128}
                  onChange={(e) => setConfirmation(e.target.value)}
                />
              </label>
              <Button disabled={busy} type="submit">
                {busy ? 'Activation…' : 'Activer mon compte'}
              </Button>
            </form>
          </>
        ) : (
          !error && <p>Vérification de votre invitation…</p>
        )}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {!done && (
          <Button variant="ghost" onClick={onDone}>
            Retour à la connexion
          </Button>
        )}
        <p className="muted small">
          NoiseFence analyse les messages ; votre messagerie reste accessible
          chez votre fournisseur habituel.
        </p>
      </section>
    </main>
  );
}
