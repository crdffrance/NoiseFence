'use client';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import type { CustomPolicy, FilteringAssessment } from './custom-filtering';
import { PolicyTraceDetails } from './policy-trace-view';
import { sampleChange } from './policy-trace';
import { actionReason } from './action-coverage';

type Result = {
  at: number;
  configuration_revision: number | null;
  sample_sha256: string;
  evaluated: number;
  changed: number;
  complete_comparisons: number;
  note: string;
  rows: {
    id: string;
    status: string;
    comparable?: boolean;
    changed?: boolean | null;
    before_category?: string;
    before_action?: string | null;
    assessment?: FilteringAssessment;
  }[];
};
export function PolicySample({
  policy,
  csrf,
}: {
  policy: CustomPolicy;
  csrf: string;
}) {
  const [recipient, setRecipient] = useState('');
  const [ids, setIds] = useState('');
  const [at, setAt] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<{
    value: Result;
    draft: string;
    recipient: string;
    ids: string;
    at: string;
  } | null>(null);
  const stale =
    result &&
    (result.draft !== JSON.stringify(policy) ||
      result.recipient !== recipient ||
      result.ids !== ids ||
      result.at !== at);
  return (
    <form
      className="panel custom-card"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError('');
        setResult(null);
        const draft = JSON.stringify(policy);
        try {
          const value = await api<Result>(
            '/admin/filtering/sample',
            {
              policy,
              recipient: recipient.trim(),
              message_ids: ids.split(/[\s,]+/).filter(Boolean),
              at: at ? Math.floor(new Date(`${at}Z`).getTime() / 1000) : null,
            },
            csrf,
          );
          setResult({ value, draft, recipient, ids, at });
        } catch (err) {
          setError((err as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <h2>Compare the draft on a fixed message sample</h2>
      <p className="muted">
        Use 1–50 message IDs delivered to one recipient. This compares policy
        effects on retained detector results, using saved global settings and
        personal preferences. Bodies and unrecorded facts stay unknown. No
        messages are rescanned, sent or changed.
      </p>
      <div className="custom-grid">
        <label htmlFor="policy-sample-recipient">
          Recipient
          <Input
            id="policy-sample-recipient"
            required
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
          />
        </label>
        <label htmlFor="policy-sample-at">
          Evaluation time (UTC, optional)
          <Input
            id="policy-sample-at"
            type="datetime-local"
            value={at}
            onChange={(e) => setAt(e.target.value)}
          />
        </label>
      </div>
      <label>
        Message IDs
        <textarea
          required
          rows={4}
          maxLength={2000}
          value={ids}
          onChange={(e) => setIds(e.target.value)}
          placeholder="One queue ID per line"
        />
      </label>
      <Button type="submit" disabled={busy}>
        {busy ? 'Comparing…' : 'Compare policy effects'}
      </Button>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div aria-live="polite">
          {stale && (
            <output>
              Draft or sample inputs changed. Run the comparison again before
              using these results.
            </output>
          )}
          <p>
            {result.value.evaluated} messages evaluated · {result.value.changed}{' '}
            changes among {result.value.complete_comparisons} complete
            comparisons.
          </p>
          <p className="muted small">
            Saved configuration revision:{' '}
            {result.value.configuration_revision ??
              'installation configuration'}{' '}
            · evaluated at {new Date(result.value.at * 1000).toISOString()}.
            Sample fingerprint: <code>{result.value.sample_sha256}</code>
          </p>
          <p className="muted small">
            {result.value.note} Unknown historical actions or missing rule facts
            are excluded from the complete comparison count.
          </p>
          {result.value.rows.map((row) => (
            <details key={row.id} className="panel">
              <summary>
                <code>{row.id}</code> · {sampleChange(row)}
              </summary>
              {row.assessment && (
                <>
                  <p>
                    Recorded: {row.before_category ?? 'unknown'} ·{' '}
                    {row.before_action ?? 'action not recorded'}
                  </p>
                  <p>
                    Simulated: {row.assessment.category} · requested{' '}
                    {row.assessment.action.requested} · effective{' '}
                    {row.assessment.action.effective}.{' '}
                    {actionReason(row.assessment.action.reason)}.
                  </p>
                  <p>
                    Content threshold: {row.assessment.threshold} · unavailable
                    conditions: {row.assessment.unavailable_conditions}
                  </p>
                  <PolicyTraceDetails trace={row.assessment.trace} />
                </>
              )}
            </details>
          ))}
        </div>
      )}
    </form>
  );
}
