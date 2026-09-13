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
  pending: "Pending",
  accepted: "Accepted",
  expired: "Expired",
  revoked: "Revoked",
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
        <h2>Invite user</h2>
      </div>
      <p className="muted">
        Users choose their own password through a personal link. Their account is created when they accept the invitation.
      </p>
      <form className="custom-card" onSubmit={create}>
        <div className="custom-grid">
          <label htmlFor="onboarding-1">
            Username
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
              <option value={1}>24 hours</option>
              <option value={3}>3 days</option>
              <option value={7}>7 days</option>
            </select>
          </label>
          <label htmlFor="onboarding-2">
            Authorized addresses or domains
            <Input
              id="onboarding-2"
              required={!form.admin}
              placeholder="alice@example.test, *@example.test"
              value={form.addresses}
              onChange={(e) => setForm({ ...form, addresses: e.target.value })}
            />
          </label>
          <label>
            Role
            <select
              value={form.admin ? 'admin' : 'user'}
              onChange={(e) =>
                setForm({ ...form, admin: e.target.value === 'admin' })
              }
            >
              <option value="user">User · specified addresses and domains</option>
              <option value="admin">Administrator · all domains</option>
            </select>
          </label>
        </div>
        {form.admin && (
          <p className="small">
            This role allows you to view all messages and modify the accounts and settings of the server.
          </p>
        )}
        <Button type="submit" disabled={busy}>
          <LinkIcon size={16} />
          {busy ? "Creation..." : "Create invitation link"}
        </Button>
        <p className="muted small">
          Creating a new link for the same username revokes earlier links. No email is sent automatically.
        </p>
      </form>
      {url && (
        <output className="invitation-result">
          <strong>Link ready to share</strong>
          <p>
            Copy it now: it will no longer be displayed after leaving this screen.
          </p>
          <Input
            aria-label="Personal invitation link"
            readOnly
            value={url}
            onFocus={(e) => e.target.select()}
          />
          <Button
            variant="outline"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(url);
                setNotice("Link copied.");
              } catch {
                setError("Select the link to manually copy it.");
              }
            }}
          >
            <Copy size={16} /> Copy Link
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
                {item.admin ? "Administrator" : item.addresses.join(', ')} ·{' '}
                {statusNames[item.status]} · until{' '}
                {new Date(item.expires * 1000).toLocaleString("en-GB")}
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
                Revoke
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
        <p>Loading…</p>
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
        <span className="eyebrow">NOISEFENCE · YOUR ACCESS</span>
        <h1>
          {done ? "Your account is ready" : "Welcome to your console"}
        </h1>
        {done ? (
          <>
            <p>
              Your password is saved. Log in with ID <strong>{identity?.username}</strong>.
            </p>
            <Button onClick={onDone}>Sign in</Button>
          </>
        ) : identity ? (
          <>
            <p>
              Enable account <strong>{identity.username}</strong> to view the analysis of your messages and report ranking errors.
            </p>
            <div className="invitation-result">
              <strong>
                {identity.admin
                  ? "Gateway Administrator"
                  : "Your access"}
              </strong>
              <p>
                {identity.admin
                  ? "All domains, accounts and settings of the gateway."
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
                Choose a password
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
                12 to 128 bytes. A long passphrase is recommended.
              </p>
              <label htmlFor="onboarding-4">
                Confirm password
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
                {busy ? 'Activation…' : "Enable my account"}
              </Button>
            </form>
          </>
        ) : (
          !error && <p>Checking your invitation...</p>
        )}
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {!done && (
          <Button variant="ghost" onClick={onDone}>
            Back to sign-in
          </Button>
        )}
        <p className="muted small">
          NoiseFence analyzes messages; your email is still available from your regular provider.
        </p>
      </section>
    </main>
  );
}
