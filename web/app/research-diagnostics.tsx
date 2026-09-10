'use client';
import {
  contribution,
  duration,
  type MessageDiagnostics,
} from './diagnostics-formatters';

const statuses: Record<string, string> = {
  complete: 'Terminé',
  incomplete: 'Partiel',
  limited: 'Limite atteinte',
  busy: 'Capacité occupée',
  unavailable: 'Indisponible',
  disabled: 'Désactivé',
  invalid_settings: 'Configuration invalide',
  invalid_message: 'Message non exploitable',
  prepared: 'Préparation terminée',
  no_candidates: 'Aucun document sélectionné',
  pending: 'En attente',
  submitting: 'Transmission en cours',
  submitted: 'Pris en charge par le connecteur',
  inconclusive: 'Analyse non concluante',
  queued: 'En file',
  running: 'Analyse en cours',
  findings: 'Observations à examiner',
  no_findings: 'Aucune observation rapportée',
  expired: 'Délai dépassé',
};
const findings: Record<string, string> = {
  html_active_element: 'Élément HTML actif',
  html_event_handler: 'Gestionnaire JavaScript HTML',
  html_active_url: 'Adresse utilisant un protocole actif',
  html_refresh: 'Redirection HTML',
  html_embedded_content: 'Contenu embarqué dans le HTML',
  type_mismatch: 'Format et type déclaré différents',
  image_dimensions: 'Dimensions d’image inhabituelles',
  image_count: 'Nombre d’images élevé',
  image_structure_invalid: 'Structure d’image invalide',
  trailing_data: 'Données après la fin du fichier',
  pdf_active_name: 'Action active dans un PDF',
  pdf_encrypted: 'PDF chiffré',
  pdf_embedded_file: 'Fichier embarqué dans un PDF',
  pdf_external_reference: 'Référence externe dans un PDF',
  pdf_malformed: 'Structure PDF invalide',
  pdf_unsupported_filter: 'Filtre PDF non pris en charge',
  pdf_unsupported_structure: 'Structure PDF non couverte',
  office_vba_project: 'Projet VBA dans un document Office',
  office_macro_enabled: 'Format Office avec macros',
  office_xlm_macros: 'Macros Excel XLM',
  office_external_relationship: 'Relation externe dans un document Office',
  office_embedded_object: 'Objet incorporé dans un document Office',
  office_encrypted: 'Document Office chiffré',
  office_legacy_coverage: 'Couverture partielle d’un ancien format Office',
  decompression_limit: 'Budget de décompression atteint',
  archive_encrypted: 'Archive chiffrée',
  archive_ambiguous: 'Archive ambiguë',
  archive_malformed: 'Archive invalide',
  unsupported_format: 'Format non couvert',
  unsupported_encoding: 'Encodage non couvert',
};

export default function ResearchDiagnostics({
  analysis,
  sandboxResults = [],
}: {
  analysis: MessageDiagnostics['analysis'];
  sandboxResults?: MessageDiagnostics['sandbox_results'];
}) {
  const execution = analysis.research_execution;
  const heuristics = analysis.heuristics;
  const content = analysis.content_inspection;
  const sandbox = analysis.sandbox_pipeline;
  if (
    !execution &&
    !heuristics &&
    !content &&
    !sandbox &&
    !sandboxResults.length
  )
    return null;
  return (
    <section className="diagnostic-section" aria-label="Moteurs expérimentaux">
      <h3>Moteurs expérimentaux</h3>
      {execution && (
        <p>
          {statuses[execution.status] ?? execution.status} ·{' '}
          {duration(execution.elapsed_ms)} · <code>{execution.version}</code>
        </p>
      )}
      <p className="diagnostic-callout">
        Ces observations servent à mesurer l’apport des nouveaux moteurs. La
        présence d’une macro, d’une image ou d’un script ne prouve pas à elle
        seule qu’un message est malveillant.
      </p>
      {heuristics && (
        <details
          className="diagnostic-disclosure"
          open={heuristics.findings.length > 0}
        >
          <summary>
            Heuristiques personnalisées ·{' '}
            {statuses[heuristics.status] ?? heuristics.status} ·{' '}
            {heuristics.findings.length} règle(s)
          </summary>
          <p>
            Version : <code>{heuristics.pattern_version}</code>. Poids candidat
            : {contribution(heuristics.candidate_weight)}. Contribution
            appliquée : {contribution(heuristics.contribution)}.
          </p>
          <p className="diagnostic-muted">
            Les poids candidats sont des paramètres de recherche, sans garantie
            de précision. Les occurrences répétées ne multiplient pas leur
            poids.
          </p>
          <ul>
            {heuristics.findings.map((finding) => (
              <li key={finding.id}>
                <strong>{finding.label}</strong> · <code>{finding.id}</code> ·
                famille {finding.family} · {finding.matches} correspondance(s) ·
                poids candidat {contribution(finding.candidate_weight)}
              </li>
            ))}
          </ul>
          {heuristics.limits_hit.length > 0 && (
            <p>
              Limites rencontrées : {heuristics.limits_hit.join(', ')}. Aucune
              contribution numérique sur cette analyse partielle.
            </p>
          )}
          <p className="diagnostic-muted">
            Empreinte des réglages : <code>{heuristics.settings_digest}</code>
          </p>
        </details>
      )}
      {content && (
        <details
          className="diagnostic-disclosure"
          open={content.findings.length > 0}
        >
          <summary>
            HTML, images et documents ·{' '}
            {statuses[content.status] ?? content.status} ·{' '}
            {content.findings.length} observation(s)
          </summary>
          <p>
            {content.stats.images} image(s), {content.stats.pdfs} PDF,{' '}
            {content.stats.office_documents} document(s) Office. Version :{' '}
            <code>{content.version}</code>.
          </p>
          <p className="diagnostic-muted">
            Inspection statique : aucun script ou document n’est exécuté par ce
            moteur. Un résultat sans observation ne constitue pas un certificat
            de sûreté.
          </p>
          {content.truncated && (
            <p className="diagnostic-callout">
              Analyse ou résultats tronqués par les limites de ressources.
            </p>
          )}
          <ul>
            {content.findings.map((finding, index) => (
              <li key={`${finding.id}:${finding.part}:${index}`}>
                {findings[finding.id] ?? 'Limite ou structure à examiner'} ·{' '}
                <code>{finding.id}</code>
                {finding.part != null && ` · partie ${finding.part + 1}`}
              </li>
            ))}
          </ul>
          <dl className="diagnostic-facts">
            {content.parts.map((part) => (
              <div key={part.index}>
                <dt>
                  Partie {part.index + 1} · {part.kind}
                </dt>
                <dd>
                  {part.bytes.toLocaleString('fr-FR')} octets
                  {part.width != null && part.height != null
                    ? ` · ${part.width} × ${part.height}`
                    : ''}{' '}
                  ·{' '}
                  {part.complete
                    ? 'Inspection terminée'
                    : 'Inspection partielle'}
                </dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      {(sandbox || sandboxResults.length > 0) && (
        <details
          className="diagnostic-disclosure"
          open={sandboxResults.length > 0}
        >
          <summary>Analyse dynamique des documents Office</summary>
          {sandbox && (
            <p>
              {statuses[sandbox.status] ?? sandbox.status} · {sandbox.selected}{' '}
              document(s) sélectionné(s), {sandbox.skipped} élément(s) non
              analysé(s).
              {sandbox.disposition === 'quarantine'
                ? ' Mise en quarantaine demandée pour les documents sélectionnés.'
                : ' Résultats consultatifs.'}
            </p>
          )}
          {sandbox?.details.length ? (
            <p>
              Limites à la réception : <code>{sandbox.details.join(', ')}</code>
              .
            </p>
          ) : null}
          <p className="diagnostic-muted">
            Les résultats proviennent du connecteur configuré par
            l’administrateur. Ils ne libèrent pas automatiquement un message.
            L’absence d’observation ne garantit pas qu’un document est sûr ;
            l’isolation de la machine d’analyse nécessite une validation
            indépendante.
          </p>
          {sandboxResults.map((entry) => (
            <section
              key={entry.part}
              className="diagnostic-section"
              aria-label={`Analyse du document ${entry.part + 1}`}
            >
              <h4>
                Partie {entry.part + 1} · {statuses[entry.state] ?? entry.state}
              </h4>
              {entry.detail && (
                <p>
                  Incident : <code>{entry.detail}</code>.
                </p>
              )}
              {entry.result && (
                <>
                  <p>
                    {statuses[entry.result.status] ?? entry.result.status} ·{' '}
                    {statuses[entry.result.outcome] ?? entry.result.outcome} ·
                    version {entry.result.engine_version ?? 'non renseignée'}.
                  </p>
                  {entry.result.detail && (
                    <p>
                      Détail : <code>{entry.result.detail}</code>.
                    </p>
                  )}
                  <ul>
                    {entry.result.findings.map((finding, index) => (
                      <li key={`${finding.id}:${index}`}>
                        <code>{finding.id}</code> · gravité {finding.severity} ·
                        confiance déclarée par le moteur {finding.confidence}.
                      </li>
                    ))}
                  </ul>
                  {entry.result.findings_truncated && (
                    <p>Liste des observations tronquée.</p>
                  )}
                </>
              )}
            </section>
          ))}
        </details>
      )}
    </section>
  );
}
