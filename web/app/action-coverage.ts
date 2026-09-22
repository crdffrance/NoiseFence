export type ActionCoverage = {
  version: string;
  partial_actions: boolean;
  basis: string;
  required: string[];
  missing: string[];
};
export function actionBasis(basis: string) {
  return ({ delivery: 'Delivery policy', complete_analysis: 'Complete analysis', primary_malware: 'Confirmed malware',
    recipient_rule: 'Explicit recipient rule', established_threat: 'Established threat evidence',
    score_threshold: 'Configured score threshold', validated_fusion: 'Validated fusion decision',
    message_kind: 'Recorded message kind', unresolved: 'No determinate classification' } as Record<string,string>)[basis] ?? 'Basis not recorded';
}
export function actionRequirement(requirement: string) {
  return ({ complete_analysis: 'Complete analysis', primary_malware: 'Trusted primary malware finding',
    matched_recipient_rule: 'Explicit rule matched using available facts', established_threat: 'Required threat evidence observed',
    usable_content: 'Content extraction completed', usable_score: 'Usable risk index', threshold_met: 'Applicable threshold reached',
    automatic_score_policy: 'Automatic score policy enabled', validated_fusion: 'Valid fusion decision for this message',
    message_kind: 'Complete marketing or newsletter finding', determinate_classification: 'Determinate classification',
    subject_rewrite: 'Subject renderer ready' } as Record<string,string>)[requirement] ?? 'Unknown requirement';
}
export function actionReason(reason: string) {
  return ({ observation: 'Observation mode: deliver without a tag', incomplete: 'Complete analysis required by the recorded policy',
    action_requirements_unmet: 'Required decision evidence is missing', subject_rewrite_unavailable: 'The subject cannot be rewritten safely',
    category_without_prefix: 'No subject prefix applies to this category', malware_priority: 'Primary malware policy takes precedence',
    category: 'Recorded category policy', custom_policy: 'Recorded recipient policy' } as Record<string,string>)[reason] ?? 'Other recorded policy reason';
}
export function coverageRequirements(coverage: ActionCoverage) {
  return [...new Set([...coverage.required,...coverage.missing])].map(id => ({id,
    label: actionRequirement(id), met: !coverage.missing.includes(id)}));
}
