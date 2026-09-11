type DecisionInput = {
  delivery_classification?: string | null;
  category: string;
  complete: boolean;
  score: number;
  tagged: boolean;
  pub_tagged: boolean;
  decision?: { source: string; outcome: string; score: number | null };
};

export type Arbitration = {
  version: string;
  baseline: { outcome: string; score: number | null };
  opinion: string;
  resolution: 'agreement' | 'disagreement' | 'ambiguous' | 'corroborated';
  decision: { outcome: string; score: number | null };
};

export function arbitrationExplanation(report?: Arbitration | null) {
  if (!report) return null;
  const label = (outcome: string) => ({ legitimate: 'Légitime', unwanted: 'Spam', undetermined: 'Indéterminé' }[outcome] ?? 'Indéterminé');
  return {
    title: ({ agreement: 'Avis concordants', disagreement: 'Avis contradictoires', ambiguous: 'Second avis incertain', corroborated: 'Autres signaux concordants' })[report.resolution],
    detail: `Classement historique : ${label(report.baseline.outcome)}. Second avis : ${label(report.opinion)}. ${report.decision.outcome === 'undetermined' ? 'Une vérification reste nécessaire ; le message n’est pas déclaré légitime.' : 'Ces avis ne constituent pas des preuves indépendantes.'}`,
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
