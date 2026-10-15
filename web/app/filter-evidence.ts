import type { DiagnosticReason } from './diagnostics-formatters';
import type { ScoringReport } from './scoring-format';
import type { ObservationReport } from './observations-format';

export const effectLabels = {
  all: 'All signals',
  raises: 'Raises index',
  lowers: 'Lowers index',
  other: 'Context & exclusions',
};
export type EffectFilter = keyof typeof effectLabels;

const signalNames: Record<string, string> = {
  model_contribution: 'Content model summary',
  malware_priority: 'Malware protection',
  spf_fail: 'SPF authentication failed',
  dkim_fail: 'DKIM verification failed',
  dmarc_fail: 'DMARC alignment failed',
  smtp_policy_unavailable: 'SMTP / DNS check unavailable',
  llm_unavailable: 'LLM analysis unavailable',
  vision_incomplete: 'Incomplete image analysis',
  context_requires_review: 'Context and detector opinions differ',
  context_benign_conflict: 'Authenticated context safeguard',
};
export function signalName(id: string) {
  if (Object.hasOwn(signalNames, id)) return signalNames[id];
  const text = id
    .replaceAll('_', ' ')
    .replace(
      /\b(spf|dkim|dmarc|arc|smtp|dns|url|urls|llm|qr|pdf|rbl)\b/gi,
      (word) => word.toUpperCase(),
    );
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Project the recorded ledger, never recompute a decision or add model summaries. */
export function evidenceRows(
  reasons: DiagnosticReason[],
  scoring?: ScoringReport | null,
) {
  const entries = new Map(
    scoring?.contributions.map((entry) => [entry.id, entry]),
  );
  const seen = new Set<string>();
  return reasons.map((reason, index) => {
    const entry = entries.get(reason.id);
    const duplicate = seen.has(reason.id);
    seen.add(reason.id);
    const summary = reason.id === 'model_contribution';
    const priority = reason.id === 'malware_priority';
    const recorded = entry
      ? duplicate && entry.retained != null
        ? 0
        : entry.retained
      : scoring && !summary
        ? reason.weight === 0
          ? 0
          : null
        : reason.weight;
    const value =
      recorded != null && Number.isFinite(recorded) ? recorded : null;
    const effect: Exclude<EffectFilter, 'all'> =
      summary || priority || value == null || value === 0
        ? 'other'
        : value > 0
          ? 'raises'
          : 'lowers';
    return {
      reason,
      index,
      entry,
      duplicate,
      summary,
      priority,
      value,
      effect,
    };
  });
}

export function matchesEvidence(
  row: ReturnType<typeof evidenceRows>[number],
  query: string,
  effect: EffectFilter,
) {
  const needle = query.trim().toLowerCase();
  return (
    (effect === 'all' || row.effect === effect) &&
    (!needle ||
      [
        row.reason.id,
        signalName(row.reason.id),
        row.reason.detail,
        row.entry?.family ?? '',
      ].some((value) => value.toLowerCase().includes(needle)))
  );
}

export const detectorFamilies: Record<string, string> = {
  content: 'Content & models',
  authentication: 'Sender authentication',
  sender_reputation: 'Sender reputation',
  url_threat: 'Links & destinations',
  file_threat: 'File reputation',
  malware: 'Malware checks',
  context: 'Message context',
};

/** Execution coverage is not a safety verdict. Comparison engines stay separate. */
export function detectorGroups(report?: ObservationReport | null) {
  if (!report || ![1, 2, 3].includes(report.version)) return [];
  const grouped = new Map<string, ObservationReport['observations']>();
  for (const observation of report.observations) {
    if (observation.role === 'comparison') continue;
    const family = Object.hasOwn(detectorFamilies, observation.family)
      ? observation.family
      : 'other';
    grouped.set(family, [...(grouped.get(family) ?? []), observation]);
  }
  return [...grouped].map(([id, observations]) => {
    const inactive = observations.filter((o) =>
      ['disabled', 'not_applicable'].includes(o.state),
    ).length;
    const limited = observations.filter(
      (o) => !['complete', 'disabled', 'not_applicable'].includes(o.state),
    ).length;
    const excluded = observations.filter((o) => o.exclusion != null).length;
    return {
      id,
      label: detectorFamilies[id] ?? 'Other checks',
      observations,
      inactive,
      limited,
      excluded,
      state: limited
        ? 'Limited'
        : inactive === observations.length
          ? 'Inactive'
          : 'Complete',
    };
  });
}
