export type PolicyOrdering = 'legacy_priority' | 'scoped';
export type PolicyTrace = {
  version: string;
  ordering: PolicyOrdering;
  profiles: {
    id: string;
    name: string;
    scope: string;
    origin: 'administrator' | 'personal';
    threshold: number | null;
    selected: boolean;
  }[];
  threshold_profile: string | null;
  threshold_locked: boolean;
  rules: {
    id: string;
    name: string;
    scope: string;
    origin: 'administrator' | 'personal';
    priority: number;
    outcome: 'matched' | 'no_match' | 'missing_facts' | 'stopped';
    unavailable: string[];
    category_before: string;
    category_after: string;
    action_before: string;
    action_after: string;
    stop: boolean;
  }[];
  stopped_by: string | null;
  category_rule: string | null;
  action_rule: string | null;
  malware_override: boolean;
};
export function orderingDescription(ordering: PolicyOrdering | undefined) {
  return ordering === 'scoped'
    ? 'Personal rules run first, then administrator rules. Within each group: organization, domain, then address; ascending priority and rule ID break ties. A matching stop prevents later rules. Personal rules cannot stop administrator rules.'
    : 'Legacy ordering: only the most specific personal preference is applied. Personal rules run first, then administrator rules, in ascending priority and rule ID order.';
}
export function traceOutcome(outcome: string) {
  return (
    (
      {
        matched: 'Matched',
        no_match: 'Did not match',
        missing_facts: 'Missing facts',
        stopped: 'Skipped after stop',
      } as Record<string, string>
    )[outcome] ?? 'Unknown outcome'
  );
}
export function thresholdSource(trace: PolicyTrace) {
  if (trace.threshold_locked)
    return 'Threshold controlled by the detector decision';
  if (!trace.threshold_profile) return 'Global filter threshold';
  const profile = trace.profiles.find((p) => p.id === trace.threshold_profile);
  return profile
    ? `${profile.name} (${profile.scope})`
    : 'Recorded source unavailable';
}

export function sampleChange(row: {
  status: string;
  comparable?: boolean;
  changed?: boolean | null;
}) {
  if (row.status !== 'simulated') return 'Not available for this recipient';
  if (!row.comparable || row.changed == null) return 'Comparison incomplete';
  return row.changed ? 'Would change' : 'Unchanged';
}
