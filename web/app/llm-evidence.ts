export type LlmGrounding = {
  version: string;
  supported: boolean;
  accepted_citations: number;
  mail_kind: string;
  issues: string[];
};
const descriptions: Record<string, string> = {
  missing_evidence: 'No usable citation',
  invalid_citation: 'Invalid source or citation',
  quote_not_found: 'Quoted evidence was not supplied',
  authentication_not_observed: 'Authentication failure was not observed',
  domain_difference_not_observed: 'Domain mismatch was not observed',
  ownership_not_observed: 'Domain ownership was not established',
  attachment_threat_not_observed: 'Attachment behaviour was not observed',
  extortion_not_observed: 'Direct extortion was not observed',
  report_without_current_request: 'No supported current sender request',
  conditional_notice_without_threat:
    'Conditional security notice without additional threat evidence',
};
export function groundingSummary(value?: LlmGrounding | null) {
  if (!value) return null;
  return {
    label: value.supported
      ? 'Evidence references verified'
      : 'Unsupported LLM evidence',
    detail: value.supported
      ? `${value.accepted_citations} reference(s) point to supplied observations. This does not prove the verdict or calibrate its confidence.`
      : `${[...new Set(value.issues.map((i) => descriptions[i] ?? 'Unsupported claim'))].join('; ')}. No LLM scoring weight or confirmed opinion is used.`,
  };
}

export function responseIssueLabel(issue?: string | null) {
  if (!issue) return null;
  return (
    (
      {
        output_limit: 'Provider output limit reached',
        invalid_envelope: 'Invalid provider response envelope',
        unsupported_completion: 'Provider did not complete the response',
        invalid_json: 'Invalid structured output',
        model_mismatch: 'Unexpected provider model',
        schema_or_verdict: 'Response violates the verdict contract',
      } as Record<string, string>
    )[issue] ?? 'Invalid provider response'
  );
}
