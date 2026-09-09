type DecisionInput = {
  category: string;
  complete: boolean;
  score: number;
  tagged: boolean;
  pub_tagged: boolean;
  decision?: { source: string; outcome: string; score: number | null };
};

// Keep the canonical decision distinct from the delivery action and feedback.
export function classification(mail: DecisionInput, threshold: number) {
  if (mail.decision?.source === 'antivirus')
    return { label: 'Malware', tone: 'spam' };
  if (!mail.complete) return { label: 'Analyse incomplète', tone: 'review' };
  if (
    mail.decision?.outcome === 'unwanted' ||
    (!mail.decision && mail.score >= threshold)
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
    return { label: 'Livré', tone: 'good' };
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
