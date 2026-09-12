type DecisionInput = {
  delivery_classification?: string | null;
  category: string;
  complete: boolean;
  score: number;
  tagged: boolean;
  pub_tagged: boolean;
  decision?: { source: string; outcome: string; score: number | null };
};

export type ScoreInput = {
  score: number | null;
  complete: boolean;
  model?: string;
  decision?: {
    source: string;
    outcome: string;
    score: number | null;
    model?: string;
  } | null;
  arbitration?: { resolution: string } | null;
  reasons?: { id: string }[];
  evidence?: { lexical_state?: string } | null;
  antivirus?: { status: string };
};

// A missing decision score is an abstention, not a missing content score.
// This presentation must never feed classification, thresholds or delivery.
export function scorePresentation(mail: ScoreInput) {
  const valid = (value: unknown): value is number =>
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 100;
  const useDecision =
    mail.decision?.source !== 'antivirus' && valid(mail.decision?.score);
  const value = useDecision
    ? mail.decision!.score
    : valid(mail.score)
      ? mail.score
      : null;
  const model = (useDecision ? mail.decision?.model : mail.model) ?? '';
  if (value === null)
    return {
      value,
      model,
      kind: 'unavailable',
      label: 'Score indisponible',
      detail:
        'Aucun score exploitable n’a été conservé. Une valeur zéro ne peut pas remplacer une analyse absente.',
    };

  if (!mail.complete) {
    const controls: Record<string, string> = {
      analysis_budget: 'budget d’analyse du contenu',
      signature_budget: 'limite des signatures',
      checks_unavailable: 'vérifications ou délai global',
      llm_unavailable: 'analyse LLM',
      semantic_unavailable: 'analyse sémantique',
      smtp_policy_unavailable: 'cohérence SMTP / DNS',
      vision_incomplete: 'OCR / codes visuels',
      complementary_signature_unavailable: 'signatures complémentaires',
    };
    const missing = [
      ...new Set(
        (mail.reasons ?? [])
          .map((r) => (Object.hasOwn(controls, r.id) ? controls[r.id] : null))
          .filter(Boolean),
      ),
    ];
    if (['unavailable', 'unscannable'].includes(mail.antivirus?.status ?? ''))
      missing.push('antivirus');
    const limited = mail.evidence?.lexical_state === 'limited';
    return {
      value,
      model,
      kind: 'partial',
      label: 'Score partiel',
      detail: `Score calculé avec les résultats disponibles${limited ? ', sur un contenu partiellement exploité' : ''}. ${missing.length ? `Contrôles incomplets : ${missing.join(', ')}. ` : ''}Les résultats manquants peuvent modifier cet indice ; l’analyse reste incomplète.${mail.decision?.source === 'antivirus' ? ' La détection antivirus conserve la priorité.' : ''}`,
    };
  }
  if (mail.model === 'dsn')
    return {
      value,
      model,
      kind: 'internal',
      label: 'Valeur interne',
      detail:
        'Notification de livraison générée par NoiseFence. Cette valeur enregistrée ne correspond pas à l’analyse d’un email entrant.',
    };
  if (mail.decision?.source === 'antivirus')
    return {
      value,
      model,
      kind: 'advisory',
      label: 'Score indicatif',
      detail:
        'Indice de contenu conservé. La détection de malware par l’antivirus prime sur ce score.',
    };
  if (mail.decision?.outcome === 'undetermined') {
    const reason =
      mail.arbitration?.resolution === 'disagreement'
        ? 'Les avis du moteur se contredisent.'
        : mail.arbitration?.resolution === 'ambiguous'
          ? 'Le second avis est incertain.'
          : mail.decision.source === 'fusion'
            ? 'La fusion ne permet pas de conclure.'
            : 'La confirmation est insuffisante.';
    return {
      value,
      model,
      kind: 'advisory',
      label: 'Score indicatif',
      detail: `${reason} Le score reste visible, mais la décision du moteur est indéterminée. Les éventuelles règles personnalisées restent distinctes. Cet indice n’est pas une probabilité de spam.`,
    };
  }
  if (useDecision && mail.decision?.source === 'fusion')
    return {
      value,
      model,
      kind: 'decision',
      label: 'Score de fusion',
      detail:
        'Estimation du modèle de fusion pour sa population de validation.',
    };
  return {
    value,
    model,
    kind: 'content',
    label: 'Indice de suspicion',
    detail:
      'Indice enregistré par le moteur sur 100. Il ne correspond pas à une probabilité de spam.',
  };
}

export type Arbitration = {
  version: string;
  baseline: { outcome: string; score: number | null };
  opinion: string;
  resolution: 'agreement' | 'disagreement' | 'ambiguous' | 'corroborated';
  decision: { outcome: string; score: number | null };
};

export function arbitrationExplanation(report?: Arbitration | null) {
  if (!report) return null;
  const label = (outcome: string) =>
    ({ legitimate: 'Légitime', unwanted: 'Spam', undetermined: 'Indéterminé' })[
      outcome
    ] ?? 'Indéterminé';
  return {
    title: {
      agreement: 'Avis concordants',
      disagreement: 'Avis contradictoires',
      ambiguous: 'Second avis incertain',
      corroborated: 'Autres signaux concordants',
    }[report.resolution],
    detail: `Classement historique : ${label(report.baseline.outcome)}. Second avis : ${label(report.opinion)}. ${report.decision.outcome === 'undetermined' ? 'Le moteur ne conclut pas ; les règles du destinataire peuvent déterminer le classement et la livraison.' : 'Ces avis ne constituent pas des preuves indépendantes.'}`,
  };
}

export function checkFailure(reason?: string | null) {
  if (!reason) return '';
  return (
    (
      {
        input: 'Contenu non exploitable par ce contrôle',
        storage: 'Stockage du cache ou des quotas indisponible',
        budget_storage: 'Comptabilité du budget indisponible',
        timeout: 'Délai maximal dépassé',
        network: 'Connexion ou vérification TLS impossible',
        authentication: 'Authentification refusée par le fournisseur',
        rate_limit: 'Limite imposée par le fournisseur',
        http: 'Erreur HTTP du fournisseur',
        response_limit: 'Réponse supérieure à la limite autorisée',
        invalid_response: 'Réponse invalide ou incompatible avec le protocole',
        accounting: 'Comptage des jetons incompatible avec le budget réservé',
      } as Record<string, string>
    )[reason] ?? 'Cause non reconnue'
  );
}

export function publicitySignal(
  report?: { status: string; verdict: string } | null,
) {
  return (
    report?.status === 'complete' &&
    ['promotion', 'newsletter'].includes(report.verdict)
  );
}

// Keep the canonical decision distinct from the delivery action and feedback.
export function classification(mail: DecisionInput, threshold?: number) {
  if (mail.decision?.source === 'antivirus')
    return { label: 'Malware', tone: 'spam' };
  if (!mail.complete) return { label: 'Analyse incomplète', tone: 'review' };
  if (mail.delivery_classification)
    return (
      (
        {
          spam: { label: 'Spam', tone: 'spam' },
          publicity: { label: 'PUB', tone: 'publicity' },
          legitimate: { label: 'Légitime', tone: 'good' },
          undetermined: { label: 'À vérifier', tone: 'review' },
        } as Record<string, { label: string; tone: string }>
      )[mail.delivery_classification] || { label: 'À vérifier', tone: 'review' }
    );
  if (
    !mail.decision &&
    (threshold === undefined || !Number.isFinite(threshold))
  )
    return { label: 'Classement historique non enregistré', tone: 'review' };
  if (
    mail.decision?.outcome === 'unwanted' ||
    (!mail.decision && threshold !== undefined && mail.score >= threshold)
  )
    return { label: 'Spam', tone: 'spam' };
  if (
    mail.decision?.outcome === 'undetermined' ||
    mail.category === 'undetermined'
  )
    return { label: 'À vérifier', tone: 'review' };
  if (mail.category === 'publicity') return { label: 'PUB', tone: 'publicity' };
  return { label: 'Légitime', tone: 'good' };
}

export function deliverySummary(recipients: { status: string }[]) {
  if (!recipients.length) return { label: 'Non renseignée', tone: '' };
  const statuses = new Set(recipients.map((r) => r.status));
  if (statuses.has('quarantined'))
    return { label: 'Quarantaine', tone: 'quarantine-status' };
  if (statuses.has('failed') || statuses.has('notified'))
    return { label: 'Échec de livraison', tone: 'spam' };
  if (statuses.has('pending') || statuses.has('sending'))
    return { label: 'En cours', tone: 'review' };
  if (statuses.size === 1 && statuses.has('delivered'))
    return { label: 'Accepté par le serveur', tone: 'good' };
  if (statuses.size === 1 && statuses.has('expired'))
    return { label: 'Expiré', tone: '' };
  if (statuses.size === 1 && statuses.has('discarded'))
    return { label: 'Supprimé', tone: '' };
  return { label: 'États multiples', tone: '' };
}

export function matchesAccount(
  account: {
    username: string;
    addresses: string[];
    admin: boolean;
    disabled: boolean;
  },
  query: string,
  filter: string,
) {
  const needle = query.trim().toLocaleLowerCase('fr-FR');
  return (
    (filter === 'all' ||
      (filter === 'admin' && account.admin) ||
      (filter === 'user' && !account.admin) ||
      (filter === 'disabled' && account.disabled)) &&
    (!needle ||
      [account.username, ...account.addresses].some((v) =>
        v.toLocaleLowerCase('fr-FR').includes(needle),
      ))
  );
}
