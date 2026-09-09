'use client';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';

export type ProtectionPolicy = {
  identity: boolean;
  links: boolean;
  campaigns: boolean;
  crdf: boolean;
  virustotal: boolean;
  protected_names: { name: string; domain: string }[];
  reply_exceptions: string[];
  link_exceptions: string[];
};
type Provider = 'crdf' | 'virustotal';
type ProviderState = {
  available: boolean;
  keys: Record<Provider, boolean>;
  quotas: Record<Provider, { minute: number; day: number }> | null;
};
const defaults: ProtectionPolicy = {
  identity: true,
  links: true,
  campaigns: true,
  crdf: false,
  virustotal: false,
  protected_names: [],
  reply_exceptions: [],
  link_exceptions: [],
};
export function ProtectionSettings({
  policy,
  onChange,
  user,
}: {
  policy: ProtectionPolicy | null;
  onChange: (value: ProtectionPolicy | null) => void;
  user: User;
}) {
  const [status, setStatus] = useState<ProviderState | null>(null),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [busy, setBusy] = useState(false),
    [keys, setKeys] = useState<Record<Provider, string>>({
      crdf: '',
      virustotal: '',
    });
  useEffect(() => {
    let active = true;
    api<ProviderState>('/admin/protection')
      .then((s) => {
        if (active) setStatus(s);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [user]);
  const update = (change: Partial<ProtectionPolicy>) =>
    onChange({ ...(policy || defaults), ...change });
  async function saveKey(provider: Provider) {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await api(
        `/admin/protection/keys/${provider}`,
        { key: keys[provider] },
        user.csrf,
      );
      setKeys((k) => ({ ...k, [provider]: '' }));
      setStatus(await api<ProviderState>('/admin/protection'));
      setNotice(
        'Clé enregistrée sur le serveur. Activez le connecteur puis appliquez les réglages.',
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel protection-settings">
      <h2>Protections complémentaires</h2>
      <p className="muted">
        Observation : ces détecteurs expliquent les risques sans modifier le
        score ni les messages livrés.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <output className="notice">{notice}</output>}
      {!status ? (
        <p>Chargement des connecteurs…</p>
      ) : !status.available ? (
        <p>Module à installer sur le serveur.</p>
      ) : (
        <>
          <label
            className="toggle-row"
            aria-label="Activer les protections complémentaires"
          >
            <span>
              <strong>Activer les protections complémentaires</strong>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-checked={!!policy}
              checked={!!policy}
              onChange={(e) =>
                onChange(e.target.checked ? { ...defaults } : null)
              }
            />
          </label>
          {policy && (
            <>
              <div className="module-grid">
                {(
                  [
                    [
                      'identity',
                      'Usurpation d’identité',
                      'Domaines ressemblants, nom protégé et adresse de réponse.',
                    ],
                    [
                      'links',
                      'Liens de phishing',
                      'Destination trompeuse, base locale, texte et QR codes.',
                    ],
                    [
                      'campaigns',
                      'Campagnes répétées',
                      'Corrections d’administrateurs du même domaine, avec recherche de contradictions.',
                    ],
                  ] as const
                ).map(([key, title, description]) => (
                  <label className="toggle-row" key={key} aria-label={title}>
                    <span>
                      <strong>{title}</strong>
                      <small>{description}</small>
                    </span>
                    <input
                      type="checkbox"
                      role="switch"
                      aria-checked={policy[key]}
                      checked={policy[key]}
                      onChange={(e) => update({ [key]: e.target.checked })}
                    />
                  </label>
                ))}
              </div>
              <h3>Noms protégés</h3>
              <p className="small muted">
                Associez chaque nom à son domaine d’envoi habituel. Les domaines
                de réception sont protégés automatiquement contre les
                ressemblances.
              </p>
              {policy.protected_names.map((identity, i) => (
                <div className="form-grid protection-identity" key={i}>
                  <label className="field" htmlFor={`protected-name-${i}`}>
                    Nom affiché
                    <Input
                      id={`protected-name-${i}`}
                      aria-label={`Nom protégé ${i + 1}`}
                      value={identity.name}
                      onChange={(e) =>
                        update({
                          protected_names: policy.protected_names.map((x, j) =>
                            j === i ? { ...x, name: e.target.value } : x,
                          ),
                        })
                      }
                    />
                  </label>
                  <label className="field" htmlFor={`protected-domain-${i}`}>
                    Domaine attendu
                    <Input
                      id={`protected-domain-${i}`}
                      aria-label={`Domaine du nom protégé ${i + 1}`}
                      value={identity.domain}
                      onChange={(e) =>
                        update({
                          protected_names: policy.protected_names.map((x, j) =>
                            j === i ? { ...x, domain: e.target.value } : x,
                          ),
                        })
                      }
                    />
                  </label>
                  <Button
                    variant="ghost"
                    onClick={() =>
                      update({
                        protected_names: policy.protected_names.filter(
                          (_, j) => j !== i,
                        ),
                      })
                    }
                  >
                    Retirer ce nom
                  </Button>
                </div>
              ))}
              <Button
                disabled={policy.protected_names.length >= 100}
                onClick={() =>
                  update({
                    protected_names: [
                      ...policy.protected_names,
                      { name: '', domain: '' },
                    ],
                  })
                }
              >
                Ajouter un nom protégé
              </Button>
              <div className="form-grid">
                {(
                  [
                    ['reply_exceptions', 'Exceptions d’adresse de réponse'],
                    ['link_exceptions', 'Exceptions de liens de suivi'],
                  ] as const
                ).map(([key, title]) => (
                  <label className="field" key={key}>
                    {title}
                    <small>
                      Un domaine exact par ligne. L’exception concerne
                      uniquement cette vérification.
                    </small>
                    <textarea
                      rows={3}
                      spellCheck={false}
                      value={policy[key].join('\n')}
                      onChange={(e) =>
                        update({ [key]: e.target.value.split('\n') })
                      }
                    />
                  </label>
                ))}
              </div>
              <h3>Services de réputation</h3>
              <p className="small muted">
                Consultation de rapports existants : domaines pour CRDF ;
                domaines et empreintes SHA-256 des pièces jointes pour
                VirusTotal. Aucun corps de message, fichier ou lien complet
                envoyé. Utilisez des clés dont la licence autorise cet usage.
              </p>
              <div className="module-grid">
                {(['crdf', 'virustotal'] as const).map((provider) => (
                  <section className="module-card" key={provider}>
                    <label className="toggle-row">
                      <span>
                        <strong>
                          {provider === 'crdf'
                            ? 'CRDF Threat Center'
                            : 'VirusTotal'}
                        </strong>
                        <small>
                          {status.keys[provider]
                            ? 'Clé enregistrée'
                            : 'Clé à renseigner'}{' '}
                          · {status.quotas?.[provider].minute}/min ·{' '}
                          {status.quotas?.[provider].day}/jour
                        </small>
                      </span>
                      <input
                        aria-label={`Activer ${provider}`}
                        type="checkbox"
                        role="switch"
                        aria-checked={policy[provider]}
                        checked={policy[provider]}
                        disabled={!status.keys[provider]}
                        onChange={(e) =>
                          update({ [provider]: e.target.checked })
                        }
                      />
                    </label>
                    <label className="field">
                      {status.keys[provider] ? 'Remplacer la clé' : 'Clé API'}
                      <Input
                        type="password"
                        autoComplete="off"
                        aria-label={`Clé API ${provider}`}
                        value={keys[provider]}
                        onChange={(e) =>
                          setKeys((k) => ({ ...k, [provider]: e.target.value }))
                        }
                      />
                    </label>
                    <Button
                      disabled={busy || keys[provider].length < 16}
                      onClick={() => saveKey(provider)}
                    >
                      Enregistrer la clé{' '}
                      {provider === 'crdf' ? 'CRDF' : 'VirusTotal'}
                    </Button>
                    <p className="small muted">
                      Clé conservée côté serveur, jamais affichée ni incluse
                      dans l’historique des réglages.
                    </p>
                  </section>
                ))}
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
}
const statuses: Record<string, string> = {
  disabled: 'désactivé',
  complete: 'terminé',
  not_configured: 'à configurer',
  not_run: 'non effectué',
  unknown: 'inconnu',
  limited: 'limite atteinte',
  busy: 'capacité occupée',
  unavailable: 'indisponible',
  quota: 'quota ou pause fournisseur',
  stale: 'données trop anciennes',
};
type ProviderReport = {
  status: string;
  checked: number;
  malicious: number;
  suspicious: number;
  unknown: number;
  cache_hits: number;
  elapsed_ms: number;
};
export type ProtectionReport = {
  version: string;
  observation_only: boolean;
  local_status: string;
  feed_status: string;
  campaign_status: string;
  campaign_match: boolean;
  campaign_conflict: boolean;
  authenticated_sender: boolean;
  crdf: ProviderReport;
  virustotal: ProviderReport;
  findings: {
    id: string;
    family: string;
    indicator: string;
    sources: string[];
    detail: string;
  }[];
  families: string[];
  elapsed_ms: number;
};
export function ProtectionDetails({ report }: { report: ProtectionReport }) {
  return (
    <section className="panel">
      <h2>Protections complémentaires</h2>
      <p className="notice">
        Observations uniquement · {report.version} · {report.elapsed_ms} ms. Les
        détections corrélées sont regroupées et ne changent pas le score actuel.
        Plusieurs services signalant le même indicateur ne constituent pas des
        votes indépendants.
      </p>
      <div className="form-grid">
        <p>
          Contrôles locaux : {statuses[report.local_status]}
          <br />
          Base de phishing : {statuses[report.feed_status]}
        </p>
        <p>
          Campagnes : {statuses[report.campaign_status]}
          {report.campaign_conflict
            ? ' · retour légitime contradictoire, correspondance non retenue'
            : report.campaign_match
              ? ' · correspondance confirmée'
              : ''}
          <br />
          Expéditeur aligné DMARC :{' '}
          {report.authenticated_sender ? 'oui' : 'non confirmé'}
        </p>
      </div>
      {(
        [
          ['CRDF', report.crdf],
          ['VirusTotal', report.virustotal],
        ] as const
      ).map(([name, r]) => (
        <div key={name}>
          <p>
            <strong>{name}</strong> :{' '}
            {statuses[r.status] ?? 'état non enregistré'} · {r.checked}{' '}
            indicateur(s) consulté(s), {r.malicious} signalé(s), {r.suspicious}{' '}
            suspect(s), {r.unknown} inconnu(s) · {r.cache_hits} en cache ·{' '}
            {r.elapsed_ms} ms
          </p>
          {r.cache_hits > 0 && (
            <p className="muted small">
              {r.cache_hits} résultat(s) réutilisé(s) du cache, sans nouvelle
              consultation du fournisseur.
            </p>
          )}
          {r.status === 'quota' && (
            <p className="muted small">
              Quota atteint ou pause imposée par le fournisseur : certaines
              consultations n’ont pas abouti. Cela ne signifie pas que le
              message est sûr.
            </p>
          )}
          {[
            'unavailable',
            'busy',
            'limited',
            'stale',
            'not_run',
            'not_configured',
            'unknown',
          ].includes(r.status) && (
            <p className="muted small">
              Couverture incomplète ou résultat inexploitable pour ce contrôle ;
              aucune absence de menace ne peut en être déduite.
            </p>
          )}
        </div>
      ))}
      {report.findings.length ? (
        <ul className="reasons">
          {report.findings.map((f, i) => (
            <li key={i}>
              <span>
                <code>{f.id}</code>
                <br />
                {f.detail}
                <small className="muted">
                  {' '}
                  ·{' '}
                  {f.sources
                    .map(
                      (s) =>
                        (
                          ({
                            headers: 'En-têtes',
                            html: 'HTML',
                            text: 'Texte',
                            ocr_qr: 'OCR / QR',
                            crdf: 'CRDF',
                            virustotal: 'VirusTotal',
                            local_feedback: 'Corrections locales',
                          }) as Record<string, string>
                        )[s] || s,
                    )
                    .join(', ')}
                </small>
              </span>
              <code>
                {(
                  {
                    identity: 'Identité',
                    link_structure: 'Liens',
                    link_reputation: 'Réputation',
                    attachment: 'Pièce jointe',
                    campaign: 'Campagne',
                  } as Record<string, string>
                )[f.family] || f.family}
              </code>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">
          Aucun indice supplémentaire relevé par les contrôles effectués.
        </p>
      )}
    </section>
  );
}
