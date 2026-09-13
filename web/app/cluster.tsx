'use client';
import { useCallback, useEffect, useState } from 'react';
import {
  Server,
  Plus,
  RefreshCw,
  ShieldCheck,
  Copy,
  X,
  ArrowRight,
} from 'lucide-react';
import { api, type User } from './client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type Replication = {
  required: boolean; peer_id: string | null; unprotected: number; pending_updates: number;
  remote_messages: number; remote_bytes: number; last_success: number | null; last_error: string | null;
};
type Node = {
  id: string;
  name: string;
  enabled: boolean;
  version: number;
  last_seen: number | null;
  applied_revision: number | null;
  applied_digest: string | null;
  status: {
    replication?: Replication;
    hostname?: string;
    poll_seconds?: number;
    queued?: number;
    quarantined?: number;
    pending_metadata?: number;
    free_bytes?: number;
    last_error?: string | null;
  };
};
type Overview = {
  replication?: Replication;
  recovery_console?: boolean;
  standby?: { created?: number; received?: number; console_url?: string; last_error?: string | null } | null;

  role: 'coordinator' | 'worker' | null;
  node_id: string | null;
  revision: number | null;
  digest: string | null;
  nodes: Node[];
  max_stale_seconds: number | null;
  commands: {
    id: string;
    node_id: string;
    recipient: string;
    created: number;
    result: string | null;
  }[];
};
type Draft = {
  id: string;
  name: string;
  enabled: boolean;
  version: number;
  rotate: boolean;
};
const date = (value: number | null) =>
  value
    ? new Date(value * 1000).toLocaleString("en-GB")
    : "Waiting for the first contact";
export function ClusterConsole({
  user,
  onDirty,
}: {
  user: User;
  onDirty: (dirty: boolean) => void;
}) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [identity, setIdentity] = useState<{
    id: string;
    credential: string;
  } | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(() => Date.now() / 1000);
  const refresh = useCallback(async (signal?: AbortSignal) => {
    const value = await api<Overview>('/admin/cluster', undefined, undefined, {
      signal,
    });
    setOverview(value);
    setClock(Date.now() / 1000);
  }, []);
  useEffect(() => {
    const abort = new AbortController();
    const load = () => {
      void refresh(abort.signal).catch((e: Error) => {
        if (!abort.signal.aborted) setError(e.message);
      });
    };
    load();
    const timer = setInterval(load, 15000);
    return () => {
      abort.abort();
      clearInterval(timer);
    };
  }, [refresh, user.username]);
  useEffect(() => {
    const dirty = draft !== null || identity !== null;
    onDirty(dirty);
    const leave = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener('beforeunload', leave);
    return () => {
      window.removeEventListener('beforeunload', leave);
      onDirty(false);
    };
  }, [draft, identity, onDirty]);
  async function save() {
    if (!draft) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<{ id: string; credential: string | null }>(
        '/admin/cluster/nodes',
        draft,
        user.csrf,
      );
      if (result.credential)
        setIdentity({ id: result.id, credential: result.credential });
      setDraft(null);
      await refresh();
      setNotice(
        "Node saved. Connection and synchronization will be checked at its next contact.",
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!overview)
    return (
      <div className="card">
        {error ? (
          <p role="alert" className="error">
            {error}
          </p>
        ) : (
          "Loading servers..."
        )}
      </div>
    );
  return (
    <div className="cluster-console">
      <div className="cluster-intro">
        <div>
          <p className="eyebrow">MAIL CONTINUITY</p>
          <h1>MX servers</h1>
          <p className="muted">
            A common policy. Each server analyses and delivers its messages independently.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => {
            void refresh().catch((e: Error) => setError(e.message));
          }}
        >
          <RefreshCw size={16} /> Refresh
        </Button>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <output className="notice">{notice}</output>}
      <div className="cluster-authority card">
        <ShieldCheck size={28} />
        <div>
          <strong>
            {overview.role === 'coordinator'
              ? `Central console · ${overview.node_id}`
              : "Local processing"}
          </strong>
          <p>
            {overview.role === 'coordinator'
              ? `Revision ${overview.revision} · Authenticated distribution of settings and models`
              : "The coordinating role must be activated during deployment to attach another server."}
          </p>
        </div>
        <span className="revision-badge">
          {
            overview.nodes.filter(
              (n) =>
                n.enabled &&
                n.last_seen &&
                clock - n.last_seen <
                  Math.max(90, 3 * (n.status.poll_seconds || 10)),
            ).length
          }{' '}
          connected
        </span>
      </div>
      {overview.recovery_console && <section className="card cluster-behavior"><h2>Active recovery console</h2><p>This instance manages the console and does not receive or relay any mail. The former coordinator must remain stopped until the return procedure. Strict reception always requires two machines available.</p></section>}
      {overview.replication?.required && (
        <section className="card cluster-behavior">
          <h2>Two mandatory durable copies</h2>
          <p>A message is accepted only after confirmation of its copy on the other MX. A replication failure causes a temporary SMTP delay before the analysis when the failure is already known.</p>
          <dl className="cluster-facts">
            <div><dt>Pending confirmations</dt><dd>{overview.replication.unprotected}</dd></div>
            <div><dt>States to be synchronized</dt><dd>{overview.replication.pending_updates}</dd></div>
            <div><dt>Copies hosted here</dt><dd>{overview.replication.remote_messages}</dd></div>
          </dl>
          <p className="small muted">Last confirmed exchange: {date(overview.replication.last_success)}</p>
          {overview.replication.last_error && <p className="error">{overview.replication.last_error}</p>}
        </section>
      )}
      {overview.standby && (
        <section className="card cluster-behavior">
          <h2>Emergency console</h2>
          <p>Last checkpoint: {date(overview.standby.created ?? null)}The promotion requires the confirmed stop of the former coordinator; it does not start any SMTP relays.</p>
          {overview.standby.console_url && <p>Recovery address: {overview.standby.console_url}</p>}
          {overview.standby.last_error && <p className="error">{overview.standby.last_error}</p>}
        </section>
      )}
      <div className="cluster-toolbar">
        <h2>Connected gateways</h2>
        <Button
          disabled={
            overview.role !== 'coordinator' ||
            busy ||
            draft !== null ||
            identity !== null
          }
          onClick={() => {
            setError('');
            setDraft({
              id: '',
              name: '',
              enabled: true,
              version: -1,
              rotate: false,
            });
          }}
        >
          <Plus size={16} /> Add MX Server
        </Button>
      </div>
      {!overview.nodes.length && (
        <div className="card cluster-empty">
          <Server size={32} />
          <h3>Prepare a second entry for your emails</h3>
          <p>
            Create its identity, install NoiseFence on an independent server, and then check the synchronization before releasing its MX record.
          </p>
        </div>
      )}
      <div className="cluster-node-grid">
        {overview.nodes.map((node) => {
          const fresh =
            node.last_seen !== null &&
            clock - node.last_seen <
              Math.max(90, 3 * (node.status.poll_seconds || 10));
          const synchronized =
            fresh &&
            node.applied_digest === overview.digest &&
            !node.status.last_error;
          const state = !node.enabled
            ? "Revoked"
            : !node.last_seen
              ? 'Not connected'
              : !fresh
                ? "Contact lost"
                : synchronized
                  ? "Synchronized"
                  : "Synchronization in progress";
          return (
            <article className="card cluster-node" key={node.id}>
              <div className="cluster-node-heading">
                <Server size={22} />
                <div>
                  <h3>{node.name}</h3>
                  <span className="muted">
                    {node.status.hostname || node.id}
                  </span>
                </div>
                <span
                  className={`cluster-state ${synchronized && node.enabled ? 'cluster-state-ok' : ''}`}
                >
                  {state}
                </span>
              </div>
              <dl className="cluster-facts">
                <div>
                  <dt>In queue</dt>
                  <dd>{node.status.queued ?? '—'}</dd>
                </div>
                <div>
                  <dt>Quarantined</dt>
                  <dd>{node.status.quarantined ?? '—'}</dd>
                </div>
                <div>
                  <dt>Revision</dt>
                  <dd>{node.applied_revision ?? '—'}</dd>
                </div>
              </dl>
              <p className="small muted">
                Last contact: {date(node.last_seen)}
              </p>
              {node.status.replication?.required && <p className="small">Mandatory replication · {node.status.replication.unprotected} confirmation(s) pending · {node.status.replication.pending_updates} status(s) to be synchronized</p>}
              {node.status.pending_metadata ? (
                <p className="small">
                  {node.status.pending_metadata} Analysis(s) to be synchronized
                </p>
              ) : null}
              {node.status.last_error && (
                <p className="error">{node.status.last_error}</p>
              )}
              <Button
                variant="outline"
                disabled={draft !== null || identity !== null}
                onClick={() =>
                  setDraft({
                    id: node.id,
                    name: node.name,
                    enabled: node.enabled,
                    version: node.version,
                    rotate: false,
                  })
                }
              >
                Configure <ArrowRight size={14} />
              </Button>
            </article>
          );
        })}
      </div>
      {draft && (
        <form
          className="card cluster-editor"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <div className="cluster-toolbar">
            <h2>
              {draft.version < 0
                ? "Add Server"
                : `Configure ${draft.id}`}
            </h2>
            <Button
              type="button"
              variant="ghost"
              aria-label="Close node configuration"
              disabled={busy}
              onClick={() => setDraft(null)}
            >
              <X size={18} />
            </Button>
          </div>
          <div className="cluster-form-grid">
            <label htmlFor="cluster-node-id">
              Username
              <Input
                id="cluster-node-id"
                required
                disabled={draft.version >= 0}
                value={draft.id}
                maxLength={40}
                pattern="[a-z0-9_-]+"
                placeholder="mx2"
                onChange={(e) => setDraft({ ...draft, id: e.target.value })}
              />
            </label>
            <label htmlFor="cluster-node-name">
              Name displayed
              <Input
                id="cluster-node-name"
                required
                value={draft.name}
                maxLength={100}
                placeholder="MX2 · Secondary site"
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>
          </div>
          <label className="cluster-check">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) =>
                setDraft({ ...draft, enabled: e.target.checked })
              }
            />{' '}
            Allow exchanges with this server
          </label>
          {draft.version >= 0 && (
            <label className="cluster-check">
              <input
                type="checkbox"
                checked={draft.rotate}
                onChange={(e) =>
                  setDraft({ ...draft, rotate: e.target.checked })
                }
              />{' '}
              Renewing your login identity
            </label>
          )}
          {draft.rotate && (
            <p className="notice">
              The old identity will stop working. Install the new identity on the node to restore synchronization.
            </p>
          )}
          {!draft.enabled && (
            <p className="notice">
              The next exchanges will be refused. An isolated node can still use its local configuration until it expires; the removal of the DNS and the shutdown of the server are separate operations.
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save Node"}
          </Button>
        </form>
      )}
      {identity && (
        <section className="card cluster-identity">
          <h2>Private identity of {identity.id}</h2>
          <p>
            Save this value in the private node file. It will no longer be displayed after closing.
          </p>
          <label>
            Login Identity
            <textarea
              readOnly
              rows={2}
              value={identity.credential}
              spellCheck={false}
            />
          </label>
          <div className="cluster-toolbar">
            <Button
              variant="outline"
              onClick={() => {
                void navigator.clipboard
                  .writeText(identity.credential)
                  .then(() => setNotice("Identity copied."))
                  .catch(() =>
                    setError(
                      "Copy not available; select the value manually.",
                    ),
                  );
              }}
            >
              <Copy size={16} /> Copy
            </Button>
            <Button onClick={() => setIdentity(null)}>
              I have registered the identity
            </Button>
          </div>
          <p className="small muted">
            The server needs its own IP, certificates and queue. Its identity authorizes synchronization of this organization’s messaging configuration and analysis history.
          </p>
        </section>
      )}
      <div className="card cluster-behavior">
        <h2>Failure behaviour</h2>
        <p>
          {overview.replication?.required
            ? "Reception requires a valid policy and confirmation from the peer. A cached policy does not permit a single copy; an unavailable peer produces a temporary SMTP deferral."
            : "The nodes continue to receive with their last valid policy, in their set autonomy duration."}
          {' '}LLM credits and allowances remain limited. Analysis and delivery statements are synchronized when the connection returns.
        </p>
        <p>
          {overview.replication?.required
            ? "Messages are copied to the peer before acceptance. Recovery requires controlled promotion and fencing to prevent two active owners. Uncertain delivery outcomes require review."
            : "Durable replication must be configured on both servers to protect already accepted messages."}
          {' '}Remote commands expire after five minutes if not executed.
        </p>
      </div>
      {!!overview.commands.length && (
        <section className="card">
          <h2>Latest Remote Commands</h2>
          <div className="cluster-command-list">
            {overview.commands.map((c) => (
              <div key={c.id}>
                <span>
                  <strong>{c.node_id}</strong> · {c.recipient}
                </span>
                <span>
                  {(
                    {
                      done: "Implemented",
                      conflict: "State changed",
                      expired: "Expires",
                      revoked: "Cancelled",
                    } as Record<string, string>
                  )[c.result || ''] || "Pending"}
                </span>
                <time>{date(c.created)}</time>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
