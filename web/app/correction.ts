import type { FeedbackCategory } from './mailing';
import type { AdaptiveClass } from './adaptive-types';

export type CorrectionScope =
  | 'operational'
  | 'development'
  | 'regression'
  | 'holdout';
export const correctionScopes: Record<
  CorrectionScope,
  { label: string; detail: string }
> = {
  operational: {
    label: 'Message correction',
    detail:
      'Saved for your account and accessible messages. Eligible corrections can inform future learning and sender history. Evaluation labels stay separate.',
  },
  development: {
    label: 'Development annotation',
    detail:
      'Saved as a sample annotation. Eligible development data may train a candidate. This does not create operational feedback or change sender trust.',
  },
  regression: {
    label: 'Regression annotation',
    detail:
      'Saved for regression evaluation. Protected messages and related campaigns remain excluded from training and sender trust.',
  },
  holdout: {
    label: 'Holdout annotation',
    detail:
      'Saved for independent evaluation. Protected messages and related campaigns remain excluded from training and sender trust. Do not tune on this sample.',
  },
};
export const correctionLabels: Record<FeedbackCategory, string> = {
  legitimate: 'Ham · wanted message',
  publicity: 'Pub · wanted marketing',
  spam: 'Spam · unwanted or fraudulent',
};
export type DomainLabel = { domain: string; class: AdaptiveClass | null };
export type CorrectionDraft = {
  mode: 'general' | 'detail' | 'withdraw';
  category: FeedbackCategory | '';
  domain: string;
  threat: 'spam' | 'phishing' | 'scam';
};
export type CorrectionRequest = {
  endpoint: 'feedback' | 'adaptive-label';
  body:
    | { category: FeedbackCategory }
    | { domain: string; class: AdaptiveClass | null };
  category?: FeedbackCategory;
  notice: string;
};
/** One explicit user action maps to one existing atomic write. Never write evaluation labels here. */
export function correctionRequest(
  draft: CorrectionDraft,
  domains: DomainLabel[] | null,
): CorrectionRequest | null {
  if (draft.mode === 'withdraw') {
    if (!domains?.some((d) => d.domain === draft.domain && d.class))
      return null;
    return {
      endpoint: 'adaptive-label',
      body: { domain: draft.domain, class: null },
      notice:
        'Detailed label withdrawn. Your general correction and evaluation annotations remain recorded.',
    };
  }
  if (!draft.category || !Object.hasOwn(correctionLabels, draft.category))
    return null;
  if (draft.mode === 'general')
    return {
      endpoint: 'feedback',
      body: { category: draft.category },
      category: draft.category,
      notice:
        'Correction saved. The recorded verdict, delivery and evaluation annotations remain unchanged.',
    };
  if (
    draft.mode !== 'detail' ||
    !domains?.some((d) => d.domain === draft.domain)
  )
    return null;
  if (!['spam', 'phishing', 'scam'].includes(draft.threat)) return null;
  const category = draft.category === 'spam' ? draft.threat : draft.category;
  return {
    endpoint: 'adaptive-label',
    body: { domain: draft.domain, class: category },
    category: draft.category,
    notice:
      'Correction and domain learning label saved together. The recorded verdict, delivery and evaluation annotations remain unchanged.',
  };
}
