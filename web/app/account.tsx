'use client';
import { useState } from 'react';
import { KeyRound, ShieldCheck, UserRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import { SecondFactor } from './mfa';

export function MyAccount({
  user,
  onPasswordChanged,
  onMfaEnabled,
}: {
  user: User;
  onPasswordChanged: () => void;
  onMfaEnabled: (codes: string[]) => void;
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
          <p className="eyebrow">YOUR ACCOUNT</p>
          <h1>My account</h1>
          <p className="muted">Your access and the security of your connection.</p>
        </div>
      </div>
      <div className="account-layout">
        <section className="panel profile-panel">
          <span className="profile-avatar">
            <UserRound size={28} />
          </span>
          <h2>{user.username}</h2>
          <span className="status">
            {user.admin ? "Administrator" : "User"}
          </span>
          <h3>
            <ShieldCheck size={18} /> Authorized scope
          </h3>
          {user.admin ? (
            <p>
              All domains and recipients in the organization.
            </p>
          ) : user.addresses.length ? (
            <ul className="access-list">
              {user.addresses.map((address) => (
                <li key={address}>{address}</li>
              ))}
            </ul>
          ) : (
            <p>
              No address assigned. Your administrator can give you access to an address or domain.
            </p>
          )}
          <p className="small muted">
            The server checks your permissions for every message and recipient.
          </p>
        </section>
        <div className="account-security">
          <SecondFactor
            user={user}
            onEnabled={onMfaEnabled}
            onDisabled={onPasswordChanged}
          />
          <form
            className="panel password-panel"
            onSubmit={async (event) => {
              event.preventDefault();
              setError('');
              if (password !== confirmation) {
                setError(
                  "The two new passwords must be identical.",
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
              <KeyRound size={20} /> Change my password
            </h2>
            <p className="muted small">
              This password protects the NoiseFence console. After modification, reconnect with the new password.
            </p>
            <label className="field" htmlFor="current-password">
              Current password
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
              New password
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
              <small>Minimum 12 characters.</small>
            </label>
            <label className="field" htmlFor="confirm-password">
              Confirm new password
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
              {busy ? "Saving…" : "Update my password"}
            </Button>
          </form>
        </div>
      </div>
    </>
  );
}
