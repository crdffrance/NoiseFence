export type ProviderTiming = {
  budget_ms: number;
  deadline_exceeded: boolean;
  phase_ms: Record<string, number>;
  cancelled: Record<string, number>;
};
const labels: Record<string, string> = {
  cache: 'Cache reads', capacity: 'Waiting for a request slot',
  storage: 'Quota and cache writes', response_headers: 'Connection, TLS and response headers',
  response_body: 'Reading the response body',
};
export function timingRows(timing: ProviderTiming) {
  return Object.entries(labels).flatMap(([phase, label]) => {
    const ms = timing.phase_ms[phase], cancelled = timing.cancelled[phase] ?? 0;
    if (!Number.isFinite(ms) || ms < 0) return [];
    return [{phase, label, ms, cancelled: Number.isInteger(cancelled) && cancelled > 0 ? cancelled : 0}];
  });
}
