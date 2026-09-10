export type UrlResolutionReport = {
  version: string;
  settings_sha256: string;
  elapsed_ms: number;
  omitted: number;
  chains: {
    source_sha256: string;
    complete: boolean;
    detail: string | null;
    hops: { url_sha256: string; site: string; code: number }[];
  }[];
};

export function UrlResolutionDetails({
  report,
}: {
  report?: UrlResolutionReport | null;
}) {
  if (!report) return null;
  return (
    <section aria-label="Redirections des liens">
      <h3>Redirections des liens</h3>
      <p className="muted small">
        {report.chains.length} lien(s) · {report.elapsed_ms} ms. Domaines
        affichés sans chemins ni paramètres privés. Une destination atteinte ne
        signifie pas que le lien est sûr.
      </p>
      {report.omitted > 0 && (
        <p className="notice">
          Au moins {report.omitted} lien(s) supplémentaire(s) non parcouru(s) :
          limite du contrôle.
        </p>
      )}
      <ol>
        {report.chains.map((chain, index) => (
          <li key={`${chain.source_sha256}-${index}`}>
            <strong>
              Lien {index + 1} ·{' '}
              {chain.complete
                ? 'Destination HTTP atteinte'
                : 'Parcours incomplet'}
            </strong>
            <p>
              {chain.hops
                .map((hop) => `${hop.site} (${hop.code})`)
                .join(' → ') || 'Aucune réponse HTTP reçue'}
            </p>
            {chain.detail && (
              <p>
                {(
                  {
                    unsafe_url: 'Adresse ou protocole non autorisé.',
                    forbidden_address:
                      'Accès à une adresse interne, réservée ou exclue bloqué.',
                    dns: 'Résolution DNS indisponible ou ambiguë.',
                    network: 'Connexion ou vérification TLS impossible.',
                    http_status:
                      'Le serveur distant ne permet pas de terminer le parcours.',
                    invalid_redirect:
                      'Redirection absente, ambiguë ou invalide.',
                    loop: 'Boucle de redirections.',
                    hop_limit: 'Nombre maximal de redirections atteint.',
                    body_limit:
                      'Page trop volumineuse ou complexe pour ce contrôle.',
                    encoding: 'Encodage de page non pris en charge.',
                    client_script:
                      'La page contient du JavaScript ; sa navigation éventuelle n’est pas exécutée.',
                    deadline: 'Budget de temps atteint.',
                    busy: 'Capacité de contrôle occupée.',
                  } as Record<string, string>
                )[chain.detail] || 'Contrôle non terminé.'}
              </p>
            )}
          </li>
        ))}
      </ol>
      <p className="muted small">
        Les domaines rencontrés sont inclus dans les rapports de réputation
        ci-dessus, selon les connecteurs actifs et leurs quotas. Les URL exactes
        sont comparées à la base locale de phishing lorsqu’elle est activée et
        disponible.
      </p>
    </section>
  );
}
