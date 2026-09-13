'use client';
import { useState } from 'react';
import { Input } from '@/components/ui/input';
import type { CustomPolicy } from './custom-filtering';
import type { ActionPolicy } from './actions';
import {
  levelValue,
  scopedProfile,
  setScopeThreshold,
  type SensitivityLevel,
} from './filter-sensitivity';

export function SensitivitySelect({
  threshold,
  levels,
  locked,
  onChange,
  label,
  inheritedLabel = "Inheritance from the general level",
}: {
  threshold: number | null;
  levels: SensitivityLevel[];
  locked: boolean;
  onChange: (value: number | null) => void;
  label: string;
  inheritedLabel?: string;
}) {
  // Preserve an explicit custom editing mode even when its value matches a preset.
  const [custom, setCustom] = useState(false);
  return (
    <div className="sensitivity-select">
      <label>
        {label}
        <select
          disabled={locked}
          value={
            custom && threshold !== null
              ? 'custom'
              : levelValue(threshold, levels)
          }
          onChange={(e) => {
            setCustom(e.target.value === 'custom');
            onChange(
              e.target.value === 'inherit'
                ? null
                : e.target.value === 'custom'
                  ? (threshold ?? 95)
                  : levels.find((l) => l.id === e.target.value)!.threshold,
            );
          }}
        >
          <option value="inherit">{inheritedLabel}</option>
          {levels.map((l, i) => (
            <option key={l.id} value={l.id}>
              {i + 1} · {l.label} · threshold {l.threshold}
            </option>
          ))}
          <option value="custom">Custom</option>
        </select>
      </label>
      {(custom || levelValue(threshold, levels) === 'custom') &&
        threshold !== null && (
          <label>
            Custom Threshold for {label.toLowerCase()}
            <Input
              type="number"
              min={50}
              max={100}
              step={0.1}
              disabled={locked}
              value={threshold}
              onChange={(e) => onChange(Number(e.target.value))}
            />
          </label>
        )}
    </div>
  );
}

export function FilterSensitivity({
  policy,
  onChange,
  domains,
  actions,
  levels,
  locked,
  modelThreshold,
}: {
  policy: CustomPolicy | null | undefined;
  onChange: (p: CustomPolicy | null) => void;
  domains: string[];
  actions: ActionPolicy;
  levels: SensitivityLevel[];
  locked: boolean;
  modelThreshold: number;
}) {
  const [error, setError] = useState('');
  const threshold = scopedProfile(policy, '*')?.threshold ?? null;
  function update(scope: string, value: number | null) {
    try {
      onChange(setScopeThreshold(policy, scope, value, actions));
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid setting.");
    }
  }
  return (
    <section
      className="panel sensitivity-panel"
      aria-labelledby="sensitivity-title"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">Sensitivity of classification</p>
          <h2 id="sensitivity-title">From the most tolerant to the most strict</h2>
        </div>
        <span className="status">5 levels</span>
      </div>
      <p className="muted">
        A stricter level lowers the threshold and increases the number of suspicious messages. Indices are not probabilities; validate the setting with your corrections.
      </p>
      {locked && (
        <p className="notice">
          Validated fusion imposes its own threshold. These settings require a new validation of fusion.
        </p>
      )}
      <fieldset
        className="sensitivity-levels"
        aria-label="Organizational level"
      >
        {levels.map((l, i) => (
          <button
            type="button"
            key={l.id}
            disabled={locked}
            aria-pressed={threshold === l.threshold}
            className="sensitivity-level"
            onClick={() => update('*', l.threshold)}
          >
            <span className="sensitivity-step">{i + 1}</span>
            <strong>{l.label}</strong>
            <span className="small">Threshold {l.threshold} / 100</span>
          </button>
        ))}
      </fieldset>
      <output className="sensitivity-explanation">
        <strong>
          {threshold === null
            ? "Inherit the engine threshold"
            : (levels.find((l) => l.threshold === threshold)?.label ??
              "Custom")}{' '}
          · threshold {threshold ?? modelThreshold}
        </strong>
        <span>
          {threshold === null
            ? "The level follows the engine reference threshold."
            : (levels.find((l) => l.threshold === threshold)?.description ??
              "The custom threshold retains the same confirmation checks.")}
        </span>
      </output>
      <SensitivitySelect
        label="General level"
        levels={levels}
        threshold={threshold}
        locked={locked}
        inheritedLabel={`Inherit the engine threshold · threshold ${modelThreshold}`}
        onChange={(v) => update('*', v)}
      />
      <p className="small muted">
        Every level preserves corroboration, disagreement arbitration, analysis limits and antivirus priority. It does not change the model or external analysis selection.
      </p>
      {domains.length > 0 && (
        <div className="sensitivity-domains">
          <h3>Domain exceptions</h3>
          <p className="small muted">
            Address-specific profiles take priority. Configure spam, marketing and review actions in Rules &amp; profiles. Changing a level preserves the current actions.
          </p>
          {domains.map((domain) => (
            <div className="sensitivity-domain" key={domain}>
              <strong>{domain}</strong>
              <SensitivitySelect
                label={`Level for ${domain}`}
                levels={levels}
                threshold={
                  scopedProfile(policy, `*@${domain}`)?.threshold ?? null
                }
                locked={locked}
                inheritedLabel={`Inheritance of the general · threshold ${threshold ?? modelThreshold}`}
                onChange={(v) => update(`*@${domain}`, v)}
              />
            </div>
          ))}
        </div>
      )}
      <p className="small">
        Use &quot;Review and apply&quot; to save these choices for future messages. Observation mode continues to transmit.
      </p>
      {error && (
        <p role="alert" className="notice">
          {error}
        </p>
      )}
    </section>
  );
}
