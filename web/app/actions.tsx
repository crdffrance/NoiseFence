'use client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

import type { ActionPolicy, DeliveryAction } from './policies';
export type { ActionPolicy, DeliveryAction } from './policies';
export type Rule = { id: string; label: string; weight: number };
export const actionLabel: Record<DeliveryAction, string> = {
  deliver: "Deliver without a tag",
  tag: "Tag and deliver",
  quarantine: "Quarantine",
};

export function ActionSettings({
  policy,
  mode,
  partialActions = false,
  spamTagReady,
  pubTagReady,
  publicityEnabled,
  onChange,
}: {
  policy: ActionPolicy;
  mode: string;
  partialActions?: boolean;
  spamTagReady: boolean;
  pubTagReady: boolean;
  publicityEnabled: boolean;
  onChange: (value: ActionPolicy) => void;
}) {
  return (
    <section className="panel delivery-actions">
      <h2>Actions after detection</h2>
      <p className="muted">
        Choose the treatment of each category. Malware detection takes precedence over spam and advertisements.
      </p>
      <div className="form-grid">
        {(
          [
            ['malware', "Malware confirmed", spamTagReady],
            ['spam', "Spam detected", spamTagReady],
            ['publicity', "Marketing / newsletter (PUB)", pubTagReady],
          ] as const
        ).map(([key, label, tagReady]) => (
          <label className="field" key={key}>
            {label}
            <select
              aria-label={`Action : ${label}`}
              value={policy[key]}
              disabled={key === 'publicity' && !publicityEnabled}
              onChange={(e) =>
                onChange({ ...policy, [key]: e.target.value as DeliveryAction })
              }
            >
              <option value="deliver">Deliver without a tag</option>
              <option value="tag" disabled={!tagReady}>
                Tag {key === 'publicity' ? '[PUB]' : '[SPAM]'} and transmit
                {!tagReady ? ' — validation required' : ''}
              </option>
              <option value="quarantine">Quarantine</option>
            </select>
            {key === 'publicity' && !publicityEnabled && (
              <small>
                Enable PUB categorization to apply this action.
              </small>
            )}
          </label>
        ))}
        <label className="field" htmlFor="quarantine-days">
          Quarantine storage (days)
          <Input
            id="quarantine-days"
            aria-label="Quarantine duration in days"
            type="number"
            min={1}
            max={30}
            step={1}
            value={policy.quarantine_days}
            onChange={(e) =>
              onChange({ ...policy, quarantine_days: Number(e.target.value) })
            }
          />
          <small>
            From 1 to 30 days. At expiry, the held delivery is discarded. Changes apply to future messages; existing expiry dates remain unchanged.
          </small>
        </label>
      </div>
      <p className="small muted">
        Users can release or discard quarantined messages for their recipients. Release delivers without a tag and preserves the classification. Feedback alone does not release a message.
      </p>
      <p className="small muted">
        {partialActions
          ? 'Partial analyses use decision-specific requirements. Missing evidence is never a detection. Tagging also requires a ready renderer; the requested and effective actions remain visible.'
          : 'An incomplete analysis delivers without a tag, unless the main antivirus confirms malware and its action is Quarantine.'}
      </p>
      {mode === 'observe' && (
        <p className="notice">
          Active observation: actions are recorded as intentions. Messages are delivered without a prefix; these actions do not quarantine them.
        </p>
      )}
    </section>
  );
}

export function RuleSettings({
  rules,
  weights,
  onChange,
}: {
  rules: Rule[];
  weights: Record<string, number>;
  onChange: (weights: Record<string, number>) => void;
}) {
  return (
    <section className="panel">
      <h2>Custom Heuristic Rules</h2>
      <p className="muted">
        Adjust each rule’s contribution to the risk index. A weight of 0 removes that numerical contribution; the observation and model features remain available.
      </p>
      <p className="small muted">
        Weights from 0 to 3 are added before conversion to the risk index. They are not percentages. Corroboration, validated fusion and antivirus priority still apply.
      </p>
      <div className="form-grid">
        {rules.map((rule) => (
          <label key={rule.id} className="field">
            {rule.label}
            <Input
              aria-label={`Weight: ${rule.label}`}
              type="number"
              min={0}
              max={3}
              step={0.1}
              value={weights[rule.id] ?? rule.weight}
              onChange={(e) =>
                onChange({ ...weights, [rule.id]: Number(e.target.value) })
              }
            />
            <small>
              Default: {rule.weight.toLocaleString("en-GB")}
            </small>
          </label>
        ))}
      </div>
      <Button
        variant="outline"
        disabled={!Object.keys(weights).length}
        onClick={() => onChange({})}
      >
        Restore default weights
      </Button>
    </section>
  );
}
