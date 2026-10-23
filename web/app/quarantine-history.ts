export type HeldRecipient = {
  address: string;
  status: string;
  held_until?: number | null;
  released_at?: number | null;
  pending_command?: string | null;
};
export type QuarantineRequest = {
  id: string;
  node: string;
  actor: string;
  action: 'release' | 'delete';
  requested_at: number;
  expires_at: number;
  result: string;
  finished_at: number | null;
  execution_result: string | null;
  acknowledged_at: number | null;
};
export type QuarantineHistory = {
  schema: 'quarantine-history-1';
  message_id: string;
  recipient: string;
  checked_at: number;
  snapshot_at: number | null;
  source: 'local' | 'replicated' | 'central';
  node: string | null;
  status: string;
  raw_available: boolean;
  held_until: number | null;
  released_at: number | null;
  pending_command: string | null;
  events: { at: number; actor: string; action: string }[];
  requests: QuarantineRequest[];
  events_truncated: boolean;
  requests_truncated: boolean;
};
export function holdState(
  r: HeldRecipient,
  at: number,
): 'held' | 'elapsed' | 'unknown' | 'pending' | 'resolved' {
  if (r.status !== 'quarantined') return 'resolved';
  if (r.held_until == null || !Number.isFinite(r.held_until)) return 'unknown';
  if (r.held_until <= at) return 'elapsed';
  return r.pending_command ? 'pending' : 'held';
}
export function requestSummary(r: QuarantineRequest, at: number): string {
  const operation = r.action === 'release' ? 'release' : 'discard';
  if (r.execution_result === 'done')
    return ['expired', 'revoked'].includes(r.result)
      ? `The request was ${r.result}, but the MX later confirmed ${operation}. Check the current delivery state.`
      : `The MX confirmed ${operation}. This is not a delivery receipt from the recipient server.`;
  if (r.execution_result === 'conflict')
    return 'The MX did not apply this command because the recipient state or stored message had changed.';
  if (r.execution_result === 'expired')
    return 'The MX reported that the command deadline had passed without applying it.';
  if (r.execution_result != null)
    return 'An unrecognized MX receipt was recorded. Contact the administrator.';
  if (r.result === 'pending' && r.expires_at > at)
    return 'Awaiting an execution receipt from the owning MX.';
  if (r.result === 'expired' || (r.result === 'pending' && r.expires_at <= at))
    return 'The request deadline passed. No execution receipt is recorded here; expiry alone does not prove that the command never ran.';
  if (r.result === 'revoked')
    return 'The request was revoked. No execution receipt is recorded here; check the current delivery state.';
  if (r.result === 'conflict')
    return 'The request ended with a state conflict. Refresh the recipient state before trying again.';
  return 'No comparable execution receipt is available. Check the current delivery state.';
}
export const quarantineEvent: Record<string, string> = {
  quarantine_release: 'Released to the delivery queue',
  quarantine_delete: 'Delivery discarded',
  quarantine_expire: 'Retention expired without delivery',
};

export function receiptAwaitingState(view: QuarantineHistory | null): boolean {
  return (
    view?.status === 'quarantined' &&
    view.requests.some((r) => r.execution_result === 'done')
  );
}
