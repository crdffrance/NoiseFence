import type { DiagnosticReason } from './diagnostics-formatters';
import type { FusionAccounting, ScoringReport } from './scoring-format';
import { detectorFamilies, evidenceRows, signalName } from './filter-evidence.ts';

export type KeyEvidence = { id: string; label: string; detail: string; value: number };

/** Rank inputs in their own recorded calculation. Never rank Rspamd or proposed weights. */
export function keyEvidence(
  source: string | undefined,
  reasons: DiagnosticReason[],
  scoring?: ScoringReport | null,
  fusion?: FusionAccounting | null,
): KeyEvidence[] {
  let inputs: KeyEvidence[] = [];
  if (source === 'fusion') {
    inputs = Object.entries(fusion?.families ?? {}).map(([id, family]) => ({
      id, label: detectorFamilies[id] ?? signalName(id),
      detail: 'Retained fusion family contribution after its limits.', value: family.retained,
    }));
  } else if (source === 'legacy' && scoring) {
    inputs = evidenceRows(reasons, scoring)
      .filter(row => !row.duplicate && !row.summary && !row.priority && row.value != null)
      .map(row => ({ id: row.reason.id, label: signalName(row.reason.id), detail: row.reason.detail, value: row.value! }));
    for (const [id, label, value] of [
      ['lexical', 'Content model', scoring.lexical],
      ['semantic', 'Semantic model', scoring.semantic],
    ] as const) {
      if (value != null) inputs.push({ id, label, detail: 'Recorded model contribution to the content index.', value });
    }
  }
  return inputs.filter(input => Number.isFinite(input.value) && input.value !== 0)
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value) || a.id.localeCompare(b.id))
    .slice(0, 3);
}
