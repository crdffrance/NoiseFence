'use client';
import { useState } from 'react';
import { Plus, Trash2, FlaskConical, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { actionLabel, type DeliveryAction } from './actions';
import { SensitivitySelect } from './filter-sensitivity-control';
import type { SensitivityLevel } from './filter-sensitivity';
type Category = 'spam' | 'publicity' | 'legitimate' | 'undetermined';
type Field =
  | 'envelope_from'
  | 'from_domain'
  | 'header_from'
  | 'subject'
  | 'body'
  | 'recipient'
  | 'recipient_domain'
  | 'size'
  | 'score'
  | 'category'
  | 'signal'
  | 'dmarc';
type Operator =
  | 'equals'
  | 'contains'
  | 'starts_with'
  | 'ends_with'
  | 'present'
  | 'absent'
  | 'at_least'
  | 'at_most';
type Condition = { field: Field; op: Operator; value: string };
export type Profile = {
  id: string;
  name: string;
  threshold: number | null;
  require_corroboration: boolean;
  spam: DeliveryAction;
  publicity: DeliveryAction;
  review: DeliveryAction;
  quarantine_days: number;
};
type Rule = {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  scope: string;
  expires: number | null;
  any: boolean;
  conditions: Condition[];
  category: Category | null;
  action: DeliveryAction | null;
  stop: boolean;
};
export type CustomPolicy = {
  profiles: Profile[];
  bindings: { scope: string; profile: string }[];
  rules: Rule[];
};
export type FilteringAssessment = {
  policy: string;
  profile: string | null;
  threshold: number;
  original_category: Category;
  category: Category;
  matched: { id: string; name: string; fields: Field[] }[];
  unavailable_conditions: number;
  action: {
    requested: DeliveryAction;
    effective: DeliveryAction;
    reason: string;
    quarantine_days: number;
  };
};
const empty: CustomPolicy = { profiles: [], bindings: [], rules: [] };
const fields: Record<Field, string> = {
  envelope_from: "Envelope sender",
  from_domain: "SMTP sender domain",
  header_from: "From address",
  subject: "Decoded subject",
  body: "MIME text",
  recipient: "Recipient address",
  recipient_domain: "Recipient domain",
  size: "Size in bytes",
  score: "Risk index",
  category: "Initial classification",
  signal: "Signal ID",
  dmarc: "DMARC result",
};
const operators: Record<Operator, string> = {
  equals: "Is equal to",
  contains: "Contains",
  starts_with: "Starts with",
  ends_with: "Ends with",
  present: "Is present",
  absent: "Is absent",
  at_least: "At least",
  at_most: "At most",
};
const categories: Record<Category, string> = {
  spam: 'Spam',
  publicity: "Marketing",
  legitimate: "Legitimate",
  undetermined: 'Needs review',
};
export function FilteringDetails({ value }: { value: FilteringAssessment }) {
  return (
    <div className="filter-assessment">
      <strong>
        {value.profile || "General policy"} · {categories[value.category]}
      </strong>
      <p>
        {actionLabel[value.action.requested]} requested ·{' '}
        {actionLabel[value.action.effective]} Implemented
        {value.action.reason === 'observation'
          ? ' (observation)'
          : value.action.reason === 'incomplete'
            ? " (incomplete analysis)"
            : ''}
      </p>
      <p className="muted small">
        Initial classification: {categories[value.original_category]} · threshold{' '}
        {value.threshold} · policy {value.policy.slice(0, 12)}
      </p>
      {value.matched.length > 0 ? (
        <ul>
          {value.matched.map((r) => (
            <li key={r.id}>
              {r.name} · {r.fields.map((f) => fields[f]).join(', ')}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted small">No custom rule triggered.</p>
      )}
      {value.unavailable_conditions > 0 && (
        <p className="muted small">
          {value.unavailable_conditions} condition(s) without data available.
        </p>
      )}
    </div>
  );
}
function ActionSelect({
  label,
  value,
  onChange,
  review = false,
}: {
  label: string;
  value: DeliveryAction;
  onChange: (v: DeliveryAction) => void;
  review?: boolean;
}) {
  return (
    <label>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as DeliveryAction)}
      >
        {(['deliver', 'tag', 'quarantine'] as const)
          .filter((a) => !review || a !== 'tag')
          .map((a) => (
            <option key={a} value={a}>
              {actionLabel[a]}
            </option>
          ))}
      </select>
    </label>
  );
}
export function CustomFiltering({
  policy,
  onChange,
  domains,
  locked,
  levels,
  csrf,
}: {
  policy: CustomPolicy | null | undefined;
  onChange: (p: CustomPolicy | null) => void;
  domains: string[];
  locked: boolean;
  levels: SensitivityLevel[];
  csrf: string;
}) {
  const p = policy || empty;
  const [sim, setSim] = useState({
    recipient: '',
    sender: '',
    subject: '',
    body: '',
    score: 20,
  });
  const [result, setResult] = useState<FilteringAssessment | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  function updateProfile(index: number, patch: Partial<Profile>) {
    onChange({
      ...p,
      profiles: p.profiles.map((v, i) =>
        i === index ? { ...v, ...patch } : v,
      ),
    });
  }
  function updateRule(index: number, patch: Partial<Rule>) {
    onChange({
      ...p,
      rules: p.rules.map((v, i) => (i === index ? { ...v, ...patch } : v)),
    });
  }
  return (
    <div className="custom-filtering">
      <div className="panel">
        <div className="section-heading">
          <SlidersHorizontal size={20} />
          <h2>A policy tailored to each recipient</h2>
        </div>
        <p className="muted">
          The exact address takes precedence over the domain, then over the organization. aliases are taken into account. Technical checks run only once per message.
        </p>
        <p className="small">
          Observation mode always transmits. Prefixes require Proton validations. Rules do not disable the priority of antivirus.
        </p>
        <datalist id="filter-scopes">
          <option value="*">The whole organisation</option>
          {domains.map((d) => (
            <option key={d} value={`*@${d}`}>
              {d}
            </option>
          ))}
        </datalist>
      </div>
      <div className="section-heading">
        <h2>Sensitivity profiles</h2>
        <Button
          disabled={p.profiles.length >= 32}
          onClick={() =>
            onChange({
              ...p,
              profiles: [
                ...p.profiles,
                {
                  id: crypto.randomUUID(),
                  name: "New profile",
                  threshold: null,
                  require_corroboration: true,
                  spam: 'quarantine',
                  publicity: 'deliver',
                  review: 'deliver',
                  quarantine_days: 14,
                },
              ],
            })
          }
        >
          <Plus size={16} /> Add Profile
        </Button>
      </div>
      {p.profiles.length === 0 && (
        <p className="empty-state">
          All recipients currently inherit the general policy.
        </p>
      )}
      {p.profiles.map((profile, i) => (
        <div className="panel custom-card" key={profile.id}>
          <div className="custom-grid">
            <label htmlFor={`custom-filtering-1-${i}`}>
              Profile Name
              <Input
                id={`custom-filtering-1-${i}`}
                value={profile.name}
                maxLength={100}
                onChange={(e) => updateProfile(i, { name: e.target.value })}
              />
            </label>
            <SensitivitySelect
              label="Sensitivity of the profile"
              levels={levels}
              locked={locked}
              threshold={profile.threshold}
              onChange={(threshold) =>
                updateProfile(i, {
                  threshold,
                  require_corroboration:
                    threshold !== null || profile.require_corroboration,
                })
              }
              inheritedLabel="Inherit the parent scope’s level"
            />
            <label htmlFor={`custom-filtering-3-${i}`}>
              Quarantine (days)
              <Input
                id={`custom-filtering-3-${i}`}
                type="number"
                min={1}
                max={30}
                value={profile.quarantine_days}
                onChange={(e) =>
                  updateProfile(i, { quarantine_days: Number(e.target.value) })
                }
              />
            </label>
            <ActionSelect
              label="Spam"
              value={profile.spam}
              onChange={(spam) => updateProfile(i, { spam })}
            />
            <ActionSelect
              label="Marketing"
              value={profile.publicity}
              onChange={(publicity) => updateProfile(i, { publicity })}
            />
            <ActionSelect
              label="Needs review"
              value={profile.review}
              review
              onChange={(review) => updateProfile(i, { review })}
            />
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={
                profile.threshold !== null || profile.require_corroboration
              }
              disabled={profile.threshold !== null}
              onChange={(e) =>
                updateProfile(i, { require_corroboration: e.target.checked })
              }
            />{' '}
            Require corroborating evidence
          </label>
          {locked && (
            <p className="muted small">
              Validated fusion imposes its own threshold. Levels do not change its calibration.
            </p>
          )}
          <Button
            variant="outline"
            onClick={() =>
              onChange({
                ...p,
                profiles: p.profiles.filter((_, n) => n !== i),
                bindings: p.bindings.filter((b) => b.profile !== profile.id),
              })
            }
          >
            <Trash2 size={15} /> Remove this profile and its assignments
          </Button>
        </div>
      ))}
      <div className="section-heading">
        <h2>Assignments</h2>
        <Button
          disabled={!p.profiles.length || p.bindings.length >= 1000}
          onClick={() =>
            onChange({
              ...p,
              bindings: [
                ...p.bindings,
                { scope: '*', profile: p.profiles[0].id },
              ],
            })
          }
        >
          <Plus size={16} /> Assign Profile
        </Button>
      </div>
      <p className="muted small">
        Use * for organization, *@domain.fr for a domain, or a full address.
      </p>
      {p.bindings.map((b, i) => (
        <div className="custom-row" key={i}>
          <Input
            aria-label="Scope of the profile"
            list="filter-scopes"
            value={b.scope}
            onChange={(e) =>
              onChange({
                ...p,
                bindings: p.bindings.map((v, n) =>
                  n === i ? { ...v, scope: e.target.value.toLowerCase() } : v,
                ),
              })
            }
          />
          <select
            aria-label="Assigned profile"
            value={b.profile}
            onChange={(e) =>
              onChange({
                ...p,
                bindings: p.bindings.map((v, n) =>
                  n === i ? { ...v, profile: e.target.value } : v,
                ),
              })
            }
          >
            {p.profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            aria-label="Delete this assignment"
            onClick={() =>
              onChange({ ...p, bindings: p.bindings.filter((_, n) => n !== i) })
            }
          >
            <Trash2 size={16} />
          </Button>
        </div>
      ))}
      <div className="section-heading">
        <h2>Customised rules</h2>
        <Button
          disabled={p.rules.length >= 100}
          onClick={() =>
            onChange({
              ...p,
              rules: [
                ...p.rules,
                {
                  id: crypto.randomUUID(),
                  name: "New Rule",
                  enabled: true,
                  priority: (p.rules.length + 1) * 10,
                  scope: '*',
                  expires: null,
                  any: false,
                  conditions: [{ field: 'subject', op: 'contains', value: '' }],
                  category: 'publicity',
                  action: null,
                  stop: true,
                },
              ],
            })
          }
        >
          <Plus size={16} /> Add Rule
        </Button>
      </div>
      <p className="muted small">
        Rules run in ascending priority. A later match can replace the previous effect unless “stop” is selected. Text matching is case-insensitive. Simulation does not open links.
      </p>
      {p.rules.map((rule, i) => (
        <div className="panel custom-card" key={rule.id}>
          <div className="custom-grid">
            <label htmlFor={`custom-filtering-4-${i}`}>
              Name
              <Input
                id={`custom-filtering-4-${i}`}
                value={rule.name}
                maxLength={100}
                onChange={(e) => updateRule(i, { name: e.target.value })}
              />
            </label>
            <label htmlFor={`custom-filtering-5-${i}`}>
              Scope
              <Input
                id={`custom-filtering-5-${i}`}
                list="filter-scopes"
                value={rule.scope}
                onChange={(e) =>
                  updateRule(i, { scope: e.target.value.toLowerCase() })
                }
              />
            </label>
            <label htmlFor={`custom-filtering-6-${i}`}>
              Priority
              <Input
                id={`custom-filtering-6-${i}`}
                type="number"
                min={0}
                max={65535}
                value={rule.priority}
                onChange={(e) =>
                  updateRule(i, { priority: Number(e.target.value) })
                }
              />
            </label>
            <label htmlFor={`custom-filtering-7-${i}`}>
              Expiration (UTC)
              <Input
                id={`custom-filtering-7-${i}`}
                type="datetime-local"
                value={
                  rule.expires
                    ? new Date(rule.expires * 1000).toISOString().slice(0, 16)
                    : ''
                }
                onChange={(e) =>
                  updateRule(i, {
                    expires: e.target.value
                      ? Math.floor(
                          new Date(`${e.target.value}Z`).getTime() / 1000,
                        )
                      : null,
                  })
                }
              />
            </label>
          </div>
          <div className="custom-row">
            <label className="check">
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(e) => updateRule(i, { enabled: e.target.checked })}
              />{' '}
              Active
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={rule.stop}
                onChange={(e) => updateRule(i, { stop: e.target.checked })}
              />{' '}
              Stop after match
            </label>
            <label>
              Conditions
              <select
                value={rule.any ? 'any' : 'all'}
                onChange={(e) =>
                  updateRule(i, { any: e.target.value === 'any' })
                }
              >
                <option value="all">All (AND)</option>
                <option value="any">At least one (OR)</option>
              </select>
            </label>
          </div>
          {rule.conditions.map((c, j) => (
            <div className="custom-row condition-row" key={j}>
              <select
                aria-label="Field"
                value={c.field}
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, field: e.target.value as Field } : v,
                    ),
                  })
                }
              >
                {Object.entries(fields).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
              <select
                aria-label="Operator"
                value={c.op}
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, op: e.target.value as Operator } : v,
                    ),
                  })
                }
              >
                {Object.entries(operators).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
              <Input
                aria-label="Value"
                disabled={c.op === 'present' || c.op === 'absent'}
                value={c.value}
                maxLength={256}
                placeholder={
                  c.field === 'category'
                    ? 'spam, publicity, legitimate, undetermined'
                    : ''
                }
                onChange={(e) =>
                  updateRule(i, {
                    conditions: rule.conditions.map((v, n) =>
                      n === j ? { ...v, value: e.target.value } : v,
                    ),
                  })
                }
              />
              <Button
                variant="outline"
                aria-label="Delete this condition"
                disabled={rule.conditions.length === 1}
                onClick={() =>
                  updateRule(i, {
                    conditions: rule.conditions.filter((_, n) => n !== j),
                  })
                }
              >
                <Trash2 size={15} />
              </Button>
            </div>
          ))}
          <Button
            variant="outline"
            disabled={rule.conditions.length >= 8}
            onClick={() =>
              updateRule(i, {
                conditions: [
                  ...rule.conditions,
                  { field: 'from_domain', op: 'equals', value: '' },
                ],
              })
            }
          >
            Add Condition
          </Button>
          <div className="custom-grid">
            <label>
              Classify as
              <select
                value={rule.category || ''}
                onChange={(e) =>
                  updateRule(i, {
                    category: (e.target.value || null) as Category | null,
                  })
                }
              >
                <option value="">Keep classification</option>
                {Object.entries(categories).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Action
              <select
                value={rule.action || ''}
                onChange={(e) =>
                  updateRule(i, {
                    action: (e.target.value || null) as DeliveryAction | null,
                  })
                }
              >
                <option value="">Inheritance of the profile</option>
                {(['deliver', 'tag', 'quarantine'] as const).map((a) => (
                  <option key={a} value={a}>
                    {actionLabel[a]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Button
            variant="outline"
            onClick={() =>
              onChange({ ...p, rules: p.rules.filter((_, n) => n !== i) })
            }
          >
            <Trash2 size={15} /> Delete Rule
          </Button>
        </div>
      ))}
      <form
        className="panel custom-card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError('');
          setResult(null);
          try {
            const data = await api<{ assessment: FilteringAssessment }>(
              '/admin/filtering/preview',
              { ...sim, policy: p },
              csrf,
            );
            setResult(data.assessment);
          } catch (err) {
            setError((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="section-heading">
          <FlaskConical size={20} />
          <h2>Simulate the draft</h2>
        </div>
        <p className="muted small">
          No messages sent or saved settings. DNS, antivirus and reputation controls remain unknown. This simulation checks the conditions entered, not the accuracy of the engine.
        </p>
        <div className="custom-grid">
          <label htmlFor="custom-filtering-8">
            Recipient
            <Input
              id="custom-filtering-8"
              required
              value={sim.recipient}
              onChange={(e) => setSim({ ...sim, recipient: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-9">
            Envelope sender
            <Input
              id="custom-filtering-9"
              value={sim.sender}
              onChange={(e) => setSim({ ...sim, sender: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-10">
            Subject
            <Input
              id="custom-filtering-10"
              value={sim.subject}
              onChange={(e) => setSim({ ...sim, subject: e.target.value })}
            />
          </label>
          <label htmlFor="custom-filtering-11">
            Simulated index
            <Input
              id="custom-filtering-11"
              type="number"
              min={0}
              max={100}
              value={sim.score}
              onChange={(e) =>
                setSim({ ...sim, score: Number(e.target.value) })
              }
            />
          </label>
        </div>
        <label>
          Text
          <textarea
            rows={3}
            value={sim.body}
            maxLength={100000}
            onChange={(e) => setSim({ ...sim, body: e.target.value })}
          />
        </label>
        <Button type="submit" disabled={busy}>
          {busy ? 'Simulation…' : "Test Rules"}
        </Button>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {result && <FilteringDetails value={result} />}
      </form>
    </div>
  );
}
