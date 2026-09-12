export const adaptiveClasses = ['legitimate', 'publicity', 'spam', 'phishing', 'scam'] as const;
export type AdaptiveClass = typeof adaptiveClasses[number];
export const adaptiveLabels: Record<AdaptiveClass, string> = {
  legitimate: 'Légitime', publicity: 'PUB', spam: 'Spam', phishing: 'Phishing', scam: 'Escroquerie',
};
export type AdaptiveReport = {
  status: string;
  model?: string | null;
  bayes_strengths?: number[] | null;
  neural_strengths?: number[] | null;
  category?: AdaptiveClass | null;
  proposed_action?: 'observe' | 'tag' | 'quarantine' | null;
  affects_delivery: false;
  calibrated: false;
};
export function adaptiveStatus(status: string): string {
  return ({ untrained: 'En attente d’un modèle entraîné', expired: 'Modèle expiré',
    scope_unavailable: 'Domaine non configuré ou plusieurs domaines destinataires',
    insufficient_features: 'Caractéristiques insuffisantes', agreement: 'Avis concordants',
    abstained: 'Abstention : accord ou confiance insuffisants',
  } as Record<string, string>)[status] ?? 'Analyse indisponible';
}
