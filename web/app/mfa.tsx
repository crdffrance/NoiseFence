'use client';
import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';

export function SecondFactor({
  user,
  onEnabled,
  onDisabled,
}: {
  user: User;
  onEnabled: (codes: string[]) => void;
  onDisabled: () => void;
}) {
  const [state, setState] = useState<{
    enabled: boolean;
    recovery_remaining: number;
  } | null>(null);
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    api<{ enabled: boolean; recovery_remaining: number }>(
      '/mfa',
      undefined,
      undefined,
      { signal: controller.signal },
    )
      .then(setState)
      .catch((e) => {
        if (!controller.signal.aborted) setError((e as Error).message);
      });
    return () => controller.abort();
  }, []);
  return (
    <section className="panel password-panel">
      <h2>
        <ShieldCheck size={20} /> Double authentification
      </h2>
      <p className="muted small">
        Ajoutez un code temporaire depuis votre application d’authentification.{' '}
        {user.admin && 'Recommandé pour votre compte administrateur.'}
      </p>
      {state && (
        <p className="status">
          {state.enabled
            ? `Activée · ${state.recovery_remaining} codes de secours restants`
            : 'À activer'}
        </p>
      )}
      {secret ? (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError('');
            try {
              const result = await api<{ recovery_codes: string[] }>(
                '/mfa/confirm',
                { code },
                user.csrf,
              );
              setSecret('');
              setCode('');
              onEnabled(result.recovery_codes);
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <p>
            Dans votre application, ajoutez un compte « NoiseFence » avec cette
            clé. Choisissez des codes basés sur le temps, à six chiffres.
          </p>
          <p className="mfa-secret">
            <code>{secret.match(/.{1,4}/g)?.join(' ')}</code>
          </p>
          <p className="small muted">
            Cette clé est personnelle. Ne la partagez pas. La configuration
            expire après dix minutes.
          </p>
          <label className="field" htmlFor="mfa-confirm">
            Code affiché par l’application
            <Input
              id="mfa-confirm"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\s/g, ''))}
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              required
            />
          </label>
          <Button type="submit" disabled={busy}>
            {busy
              ? 'Vérification…'
              : 'Activer et afficher les codes de secours'}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => {
              setSecret('');
              setCode('');
            }}
          >
            Annuler
          </Button>
        </form>
      ) : (
        state && (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError('');
              try {
                if (state.enabled) {
                  await api('/mfa/disable', { password, code }, user.csrf);
                  setPassword('');
                  setCode('');
                  onDisabled();
                } else {
                  const result = await api<{ secret: string }>(
                    '/mfa/enroll',
                    { password },
                    user.csrf,
                  );
                  setPassword('');
                  setSecret(result.secret);
                }
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label className="field" htmlFor="mfa-password">
              Confirmez votre mot de passe
              <Input
                id="mfa-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                maxLength={128}
                required
              />
            </label>
            {state.enabled && (
              <label className="field" htmlFor="mfa-disable-code">
                Nouveau code temporaire ou code de secours
                <Input
                  id="mfa-disable-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.trim())}
                  autoComplete="one-time-code"
                  maxLength={32}
                  required
                />
                <small>La désactivation déconnecte toutes vos sessions.</small>
              </label>
            )}
            <Button type="submit" disabled={busy}>
              {busy
                ? 'Vérification…'
                : state.enabled
                  ? 'Désactiver la double authentification'
                  : 'Configurer mon application'}
            </Button>
          </form>
        )
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

export function RecoveryCodes({
  codes,
  onDone,
}: {
  codes: string[];
  onDone: () => void;
}) {
  const [saved, setSaved] = useState(false);
  return (
    <main className="connection-screen">
      <section className="panel mfa-recovery">
        <ShieldCheck size={32} />
        <h1>Votre compte est protégé.</h1>
        <p>
          Enregistrez ces dix codes dans votre gestionnaire de mots de passe.
          Chacun permet une seule connexion si votre application est
          indisponible. Ils ne seront plus affichés.
        </p>
        <ul>
          {codes.map((code) => (
            <li key={code}>
              <code>{code}</code>
            </li>
          ))}
        </ul>
        <label className="check">
          <input
            type="checkbox"
            checked={saved}
            onChange={(e) => setSaved(e.target.checked)}
          />{' '}
          J’ai enregistré mes codes de secours.
        </label>
        <p className="small muted">
          Toutes vos anciennes sessions sont déconnectées. Pour la prochaine
          connexion, attendez le nouveau code de votre application ou utilisez
          un code de secours.
        </p>
        <Button disabled={!saved} onClick={onDone}>
          Retour à la connexion
        </Button>
      </section>
    </main>
  );
}
