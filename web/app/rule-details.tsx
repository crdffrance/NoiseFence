import {
  contribution,
  decisionExplanation,
  weightEffect,
  type DiagnosticReason,
} from './diagnostics-formatters';

export function RuleDetails({
  reasons,
  source,
}: {
  reasons: DiagnosticReason[];
  source?: string;
}) {
  return (
    <div className="rule-diagnostics">
      <h3 className="subheading">Filtres et indices déclenchés</h3>
      <p>{decisionExplanation(source)}</p>
      <p className="diagnostic-muted">
        Les contributions en log-odds modifient le calcul de suspicion avant sa
        conversion en score. Ce ne sont ni des points, ni des pourcentages, ni
        des votes indépendants. Leur somme n’a pas à faire 100.
      </p>
      {reasons.length ? (
        <ul className="diagnostic-rules">
          {reasons.map((reason, index) => (
            <li key={`${reason.id}-${index}`}>
              <div>
                <code className="diagnostic-rule-id">{reason.id}</code>
                <p>{reason.detail}</p>
                <p className="diagnostic-muted">
                  {reason.id === 'malware_priority'
                    ? 'Priorité antivirus · ce signal ne constitue pas un poids probabiliste.'
                    : weightEffect(reason.weight)}
                </p>
                {reason.id === 'model_contribution' && (
                  <p className="diagnostic-muted">
                    Récapitulatif du modèle lexical et sémantique déjà inclus
                    dans le calcul ; ne pas l’ajouter une seconde fois.
                  </p>
                )}
              </div>
              <span className="diagnostic-weight">
                {reason.id === 'malware_priority' ? (
                  'Prioritaire'
                ) : (
                  <>
                    <strong>{contribution(reason.weight)}</strong>
                    <small>log-odds</small>
                  </>
                )}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="diagnostic-muted">
          Aucun filtre ou indice enregistré pour ce message.
        </p>
      )}
    </div>
  );
}
