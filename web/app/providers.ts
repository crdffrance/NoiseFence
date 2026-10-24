import type { ProviderState } from './protection';
import { llmPricingStatus } from './llm-pricing.ts';

export type Budget = {
  status: 'not_started' | 'available';
  month?: string;
  accounted_micro_eur?: number;
  requests?: number;
  worker_wallet?: boolean;
  issued_micro_eur?: number;
  ceiling_micro_eur?: number;
  remaining_micro_eur?: number;
};
export type LlmService = {
  installed: boolean;
  enabled: boolean;
  configuration: {
    model: string;
    monthly_budget_micro_eur: number;
    pricing_checked_at: number;
    max_text_bytes: number;
    timeout_ms: number;
    max_parallel: number;
    score_low: number;
    score_high: number;
    review_unconfirmed_high: boolean;
  } | null;
  budget: Budget | null;
};
export type ProviderOverview = ProviderState & {
  checked_at: number;
  hostname: string;
  node_id: string | null;
  cluster_role: 'coordinator' | 'worker' | null;
  policy: { crdf: boolean; virustotal: boolean; follow_urls: boolean } | null;
  services: {
    llm: LlmService;
    rspamd: {
      enabled: boolean;
      sample_percent: number;
      timeout_ms: number;
      max_parallel: number;
    } | null;
    rbl: {
      enabled_lists: number;
      action: string;
      timeout_ms: number;
      max_parallel: number;
    } | null;
  };
};
export function llmState(service: LlmService, at: number) {
  if (!service.installed) return 'Not installed';
  if (!service.enabled || !service.configuration)
    return 'Disabled in the loaded policy';
  if (service.configuration.monthly_budget_micro_eur === 0)
    return 'Suspended · zero budget';
  const pricing = llmPricingStatus(
    service.configuration.pricing_checked_at,
    at,
  );
  if (pricing.state === 'expired' || pricing.state === 'unknown')
    return 'Suspended · pricing verification required';
  if (!service.budget) return 'Budget ledger unavailable';
  if (service.budget.status === 'not_started')
    return 'Budget ledger not initialized';
  if (
    service.budget.status === 'available' &&
    service.budget.remaining_micro_eur === 0
  )
    return service.budget.worker_wallet
      ? 'No local credit remaining'
      : 'Monthly budget fully reserved';
  return 'Enabled · subject to selection and capacity';
}
export function reputationState(
  state: ProviderOverview,
  name: 'crdf' | 'virustotal',
) {
  if (!state.available) return 'Not installed';
  if (!state.policy?.[name]) return 'Disabled in the loaded policy';
  if (!state.loaded_keys?.[name]) return 'Loaded credential not confirmed';
  if ((state.usage[name]?.cooldown_until ?? 0) > state.checked_at)
    return 'Provider cooldown';
  const quota = state.quotas?.[name],
    usage = state.usage[name];
  if (!usage) return 'Quota ledger unavailable';
  if (
    quota &&
    ((quota.day > 0 && usage.day_used >= quota.day) ||
      (quota.minute > 0 && usage.minute_used >= quota.minute))
  )
    return 'Quota fully reserved';
  return 'Enabled · upstream access not tested';
}
export function euro(amount: number | null | undefined) {
  return amount == null || !Number.isFinite(amount)
    ? 'Unavailable'
    : (amount / 1_000_000).toLocaleString('en-GB', {
        style: 'currency',
        currency: 'EUR',
        minimumFractionDigits: 2,
        maximumFractionDigits: 4,
      });
}
