export type Phase = 'preparing' | 'committed' | 'released' | 'aborted';
export type Epoch = { sequence: number; revision: number; digest: string };
export type Activation = {
  coordinator: boolean;
  coordinated: boolean;
  pending: boolean;
  installed_revision: number;
  committed_revision: number | null;
  smtp_ready: boolean;
  phase: Phase | null;
  epoch: Epoch | null;
  participants: Record<string, 'waiting' | 'prepared' | 'applied'> | null;
  abortable: boolean;
  recoverable: boolean;
  personal_change: { scope: string; revision: number; phase: Phase } | null;
  incident: { at: number; code: string } | null;
};
export type SaveResult = { revision: number; staged: boolean };
export function saveNotice(result: SaveResult): string {
  return result.staged
    ? `Revision ${result.revision} submitted for coordinated activation. Check its status in the activation panel.`
    : `Revision ${result.revision} applied to future messages.`;
}
export function activationLabel(value: Activation): string {
  if (!value.coordinated) return 'Local configuration saves';
  if (value.incident) return 'Activation needs attention';
  if (value.phase === 'preparing') return 'Preparing the policy on every MX';
  if (value.phase === 'committed')
    return 'Committed · waiting for every MX to install';
  if (value.phase === 'aborted')
    return value.smtp_ready
      ? 'Change cancelled'
      : 'Restoring the previous policy';
  if (value.phase === 'released')
    return value.smtp_ready
      ? 'Release authorized · local SMTP ready'
      : 'Release authorized · local SMTP resuming';
  return 'Waiting for activation';
}
export function savesBlocked(value: Activation | null, error: string): boolean {
  return !value || !!error || value.pending;
}

export function incidentDescription(
  code: string,
  administrator: boolean,
): string {
  if (!administrator)
    return 'Contact your administrator. The change has not been confirmed as active.';
  switch (code) {
    case 'approval_changed':
      return 'The approving account or its permissions changed. Cancel the proposal and submit it with current permissions.';
    case 'membership_changed':
      return 'The registered MX membership changed. Restore the intended membership and resolve the rollout before changing topology.';
    case 'runtime_preparation_failed':
      return 'The local runtime could not prepare or install the policy. Check model files, provider configuration and server logs.';
    default:
      return 'Check the MX status and server logs. Activation retries automatically after the cause is fixed.';
  }
}
