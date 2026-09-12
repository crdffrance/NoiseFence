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

type Node = {
  id: string;
  name: string;
  enabled: boolean;
  version: number;
  last_seen: number | null;
  applied_revision: number | null;
  applied_digest: string | null;
  status: {
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
    ? new Date(value * 1000).toLocaleString('fr-FR')
    : 'En attente du premier contact';
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
        'Nœud enregistré. La connexion et la synchronisation seront vérifiées à son prochain contact.',
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
          'Chargement des serveurs…'
        )}
      </div>
    );
  return (
    <div className="cluster-console">
      <div className="cluster-intro">
        <div>
          <p className="eyebrow">CONTINUITÉ DE LA MESSAGERIE</p>
          <h1>Serveurs MX</h1>
          <p className="muted">
            Une politique commune. Chaque serveur analyse et livre ses messages
            de manière autonome.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => {
            void refresh().catch((e: Error) => setError(e.message));
          }}
        >
          <RefreshCw size={16} /> Actualiser
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
              ? `Console centrale · ${overview.node_id}`
              : 'Instance indépendante'}
          </strong>
          <p>
            {overview.role === 'coordinator'
              ? `Révision ${overview.revision} · Distribution authentifiée des réglages et des modèles`
              : 'Le rôle de coordinateur doit être activé lors du déploiement pour rattacher un autre serveur.'}
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
          connecté(s)
        </span>
      </div>
      <div className="cluster-toolbar">
        <h2>Passerelles rattachées</h2>
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
          <Plus size={16} /> Ajouter un serveur MX
        </Button>
      </div>
      {!overview.nodes.length && (
        <div className="card cluster-empty">
          <Server size={32} />
          <h3>Préparer une seconde entrée pour vos emails</h3>
          <p>
            Créez son identité, installez NoiseFence sur un serveur indépendant,
            puis vérifiez la synchronisation avant de publier son enregistrement
            MX.
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
            ? 'Révoqué'
            : !node.last_seen
              ? 'À connecter'
              : !fresh
                ? 'Contact interrompu'
                : synchronized
                  ? 'Synchronisé'
                  : 'Synchronisation en cours';
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
                  <dt>En file</dt>
                  <dd>{node.status.queued ?? '—'}</dd>
                </div>
                <div>
                  <dt>Quarantaine</dt>
                  <dd>{node.status.quarantined ?? '—'}</dd>
                </div>
                <div>
                  <dt>Révision</dt>
                  <dd>{node.applied_revision ?? '—'}</dd>
                </div>
              </dl>
              <p className="small muted">
                Dernier contact : {date(node.last_seen)}
              </p>
              {node.status.pending_metadata ? (
                <p className="small">
                  {node.status.pending_metadata} analyse(s) à synchroniser
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
                Configurer <ArrowRight size={14} />
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
                ? 'Ajouter un serveur'
                : `Configurer ${draft.id}`}
            </h2>
            <Button
              type="button"
              variant="ghost"
              aria-label="Fermer la configuration du nœud"
              disabled={busy}
              onClick={() => setDraft(null)}
            >
              <X size={18} />
            </Button>
          </div>
          <div className="cluster-form-grid">
            <label htmlFor="cluster-node-id">
              Identifiant
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
              Nom affiché
              <Input
                id="cluster-node-name"
                required
                value={draft.name}
                maxLength={100}
                placeholder="MX2 · Site secondaire"
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
            Autoriser les échanges avec ce serveur
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
              Renouveler son identité de connexion
            </label>
          )}
          {draft.rotate && (
            <p className="notice">
              L’ancienne identité cessera de fonctionner. Installez la nouvelle
              sur le nœud pour rétablir la synchronisation.
            </p>
          )}
          {!draft.enabled && (
            <p className="notice">
              Les prochains échanges seront refusés. Un nœud isolé peut encore
              utiliser sa configuration locale jusqu’à son expiration ; le
              retrait du DNS et l’arrêt du serveur sont des opérations
              distinctes.
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? 'Enregistrement…' : 'Enregistrer le nœud'}
          </Button>
        </form>
      )}
      {identity && (
        <section className="card cluster-identity">
          <h2>Identité privée de {identity.id}</h2>
          <p>
            Enregistrez cette valeur dans le fichier privé du nœud. Elle ne sera
            plus affichée après fermeture.
          </p>
          <label>
            Identité de connexion
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
                  .then(() => setNotice('Identité copiée.'))
                  .catch(() =>
                    setError(
                      'Copie indisponible ; sélectionnez la valeur manuellement.',
                    ),
                  );
              }}
            >
              <Copy size={16} /> Copier
            </Button>
            <Button onClick={() => setIdentity(null)}>
              J’ai enregistré l’identité
            </Button>
          </div>
          <p className="small muted">
            Le serveur doit posséder sa propre IP, ses certificats et sa file.
            Son identité autorise la synchronisation de la messagerie de cette
            organisation.
          </p>
        </section>
      )}
      <div className="card cluster-behavior">
        <h2>Comportement en cas de panne</h2>
        <p>
          Les nœuds continuent à recevoir avec leur dernière politique valide,
          dans leur durée d’autonomie configurée. Leurs crédits LLM et quotas
          restent bornés. Les analyses et états de livraison sont synchronisés
          au retour de la connexion.
        </p>
        <p>
          Les corps restent sur le serveur qui les a acceptés. La présence de
          deux MX ne réplique pas les messages déjà en file. Les commandes
          distantes expirent après cinq minutes si elles ne sont pas exécutées.
        </p>
      </div>
      {!!overview.commands.length && (
        <section className="card">
          <h2>Dernières commandes distantes</h2>
          <div className="cluster-command-list">
            {overview.commands.map((c) => (
              <div key={c.id}>
                <span>
                  <strong>{c.node_id}</strong> · {c.recipient}
                </span>
                <span>
                  {(
                    {
                      done: 'Exécutée',
                      conflict: 'État modifié',
                      expired: 'Expirée',
                      revoked: 'Annulée',
                    } as Record<string, string>
                  )[c.result || ''] || 'En attente'}
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
