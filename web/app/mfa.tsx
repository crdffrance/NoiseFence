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
        <ShieldCheck size={20} /> Two-factor authentication
      </h2>
      <p className="muted small">
        Add a temporary code from your authentication application.{' '}
        {user.admin && "Recommended for your admin account."}
      </p>
      {state && (
        <p className="status">
          {state.enabled
            ? `Activated · ${state.recovery_remaining} remaining emergency codes`
            : 'Not enabled'}
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
            In your application, add a &quot;NoiseFence&quot; account with this key. Choose time-based, six-digit codes.
          </p>
          <p className="mfa-secret">
            <code>{secret.match(/.{1,4}/g)?.join(' ')}</code>
          </p>
          <p className="small muted">
            This key is personal. Do not share it. The configuration expires after ten minutes.
          </p>
          <label className="field" htmlFor="mfa-confirm">
            Code displayed by application
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
              ? "Check..."
              : "Enable and display emergency codes"}
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
            Cancel
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
              Confirm your password
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
                New temporary code or emergency code
                <Input
                  id="mfa-disable-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.trim())}
                  autoComplete="one-time-code"
                  maxLength={32}
                  required
                />
                <small>Disabling disconnects all your sessions.</small>
              </label>
            )}
            <Button type="submit" disabled={busy}>
              {busy
                ? "Check..."
                : state.enabled
                  ? "Disable two-factor authentication"
                  : "Configure my application"}
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
        <h1>Your account is protected.</h1>
        <p>
          Save these ten codes in your password manager. Each allows a single connection if your application is unavailable. They will no longer be displayed.
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
          I&apos;ve saved my emergency codes.
        </label>
        <p className="small muted">
          All your old sessions are offline. For the next connection, wait for the new code of your application or use a backup code.
        </p>
        <Button disabled={!saved} onClick={onDone}>
          Back to sign-in
        </Button>
      </section>
    </main>
  );
}
