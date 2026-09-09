'use client';
import { useState } from 'react';
import { KeyRound, ShieldCheck, UserRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';

export function MyAccount({
  user,
  onPasswordChanged,
}: {
  user: User;
  onPasswordChanged: () => void;
}) {
  const [current, setCurrent] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">VOTRE ESPACE</p>
          <h1>Mon compte</h1>
          <p className="muted">Vos accès et la sécurité de votre connexion.</p>
        </div>
      </div>
      <div className="account-layout">
        <section className="panel profile-panel">
          <span className="profile-avatar">
            <UserRound size={28} />
          </span>
          <h2>{user.username}</h2>
          <span className="status">
            {user.admin ? 'Administrateur' : 'Utilisateur'}
          </span>
          <h3>
            <ShieldCheck size={18} /> Périmètre autorisé
          </h3>
          {user.admin ? (
            <p>
              Tous les domaines et tous les destinataires de l’organisation.
            </p>
          ) : user.addresses.length ? (
            <ul className="access-list">
              {user.addresses.map((address) => (
                <li key={address}>{address}</li>
              ))}
            </ul>
          ) : (
            <p>
              Aucune adresse attribuée. Votre administrateur peut vous donner
              accès à une adresse ou à un domaine.
            </p>
          )}
          <p className="small muted">
            Les droits sont vérifiés par le serveur pour chaque message et
            chaque destinataire.
          </p>
        </section>
        <form
          className="panel password-panel"
          onSubmit={async (event) => {
            event.preventDefault();
            setError('');
            if (password !== confirmation) {
              setError(
                'Les deux nouveaux mots de passe doivent être identiques.',
              );
              return;
            }
            setBusy(true);
            try {
              await api(
                '/password',
                { current_password: current, new_password: password },
                user.csrf,
              );
              onPasswordChanged();
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <h2>
            <KeyRound size={20} /> Changer mon mot de passe
          </h2>
          <p className="muted small">
            Ce mot de passe protège la console NoiseFence. Après modification,
            reconnectez-vous avec le nouveau mot de passe.
          </p>
          <label className="field" htmlFor="current-password">
            Mot de passe actuel
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
              maxLength={128}
            />
          </label>
          <label className="field" htmlFor="new-password">
            Nouveau mot de passe
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              maxLength={128}
            />
            <small>12 caractères minimum.</small>
          </label>
          <label className="field" htmlFor="confirm-password">
            Confirmer le nouveau mot de passe
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              required
              minLength={12}
              maxLength={128}
              aria-invalid={!!error && password !== confirmation}
            />
          </label>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? 'Enregistrement…' : 'Mettre à jour mon mot de passe'}
          </Button>
        </form>
      </div>
    </>
  );
}
