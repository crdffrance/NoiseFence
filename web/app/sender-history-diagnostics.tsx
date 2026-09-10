import type { DiagnosticRecipient } from './diagnostics-formatters';

export default function SenderHistoryDiagnostics({
  report,
}: {
  report: NonNullable<DiagnosticRecipient['sender_history']>;
}) {
  return (
    <details className="diagnostic-disclosure">
      <summary>Historique de confiance pour ce destinataire</summary>
      <p>
        État : {report.status} · <code>{report.version}</code>.
      </p>
      {report.status === 'complete' && (
        <>
          <p>
            {report.distinct_campaigns} campagne(s) distincte(s),{' '}
            {report.distinct_days} période(s) de réception espacée(s).
          </p>
          <p>
            {report.contradicted
              ? 'Un retour spam autorisé contredit cette relation.'
              : report.learned_candidate
                ? 'Historique humain suffisamment diversifié pour proposer une adaptation.'
                : 'Historique insuffisant pour proposer une adaptation apprise.'}
          </p>
          {report.manual_match !== 'none' && (
            <p>
              Correspondance avec une identité de confiance configurée (
              {report.manual_match === 'exact'
                ? 'adresse exacte'
                : 'domaine exact'}
              ).
            </p>
          )}
        </>
      )}
      {report.applied ? (
        <>
          <p>
            Seuil appliqué à cette livraison :{' '}
            <strong>{report.applied.threshold.toLocaleString('fr-FR')}</strong>.
            Le score du modèle reste inchangé.
          </p>
          <p>
            {report.applied.optional_llm_omitted
              ? 'Analyse LLM facultative omise pour cette livraison. Les contrôles obligatoires ont été exécutés.'
              : 'Cette adaptation ne rapporte aucune omission d’analyse LLM.'}
          </p>
          <p>
            Politique : <code>{report.applied.version}</code>.
          </p>
        </>
      ) : (
        <p>Aucune adaptation appliquée à cette livraison.</p>
      )}
      <p className="diagnostic-muted">
        Historique propre à ce destinataire, réévalué à chaque réception. Il ne
        garantit pas l’innocuité du message ni la confiance des prochains
        échanges.
      </p>
    </details>
  );
}
