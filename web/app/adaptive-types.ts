export const adaptiveClasses = ['legitimate', 'publicity', 'spam', 'phishing', 'scam'] as const;
export type AdaptiveClass = typeof adaptiveClasses[number];
export const adaptiveLabels: Record<AdaptiveClass, string> = {
  legitimate: "Legitimate", publicity: "Marketing", spam: 'Spam', phishing: 'Phishing', scam: "Scam",
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
  return ({ untrained: "Waiting for a trained model", expired: "Model expired",
    scope_unavailable: "Unconfigured domain or multiple recipient domains",
    insufficient_features: "Insufficient features", agreement: "Opinions agree",
    abstained: "Abstention: insufficient agreement or confidence",
  } as Record<string, string>)[status] ?? "Analysis not available";
}
