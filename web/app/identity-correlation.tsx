import { Fingerprint } from 'lucide-react';
export type IdentityPolicy = {
  mode: 'observation' | 'contribute';
  maximum_weight: number;
};
export function identityPolicyError(
  value?: IdentityPolicy | null,
): string | null {
  return value &&
    (!['observation', 'contribute'].includes(value.mode) ||
      !Number.isFinite(value.maximum_weight) ||
      value.maximum_weight < 0 ||
      value.maximum_weight > 1)
    ? 'Choose an identity contribution between 0 and 1 log-odds unit.'
    : null;
}
export function IdentityPolicyEditor({
  value,
  disabled,
  onChange,
}: {
  value?: IdentityPolicy | null;
  disabled: boolean;
  onChange: (value: IdentityPolicy) => void;
}) {
  const policy = value ?? { mode: 'observation', maximum_weight: 1 };
  return (
    <section className="card" aria-label="Identity contribution policy">
      <div className="identity-heading">
        <Fingerprint size={22} aria-hidden="true" />
        <div>
          <h2>Identity contribution</h2>
          <p>
            Connect corroborated identity changes to the content risk index.
          </p>
        </div>
      </div>
      <fieldset disabled={disabled} className="contact-learning-fields">
        <legend>Decision policy</legend>
        <label>
          Mode
          <select
            value={policy.mode}
            onChange={(event) =>
              onChange({
                ...policy,
                mode: event.target.value as IdentityPolicy['mode'],
              })
            }
          >
            <option value="observation">Observe changes only</option>
            <option value="contribute">Apply bounded contribution</option>
          </select>
        </label>
        <label>
          Maximum contribution (log-odds units)
          <input
            type="number"
            min={0}
            max={1}
            step={0.1}
            value={policy.maximum_weight}
            onChange={(event) =>
              onChange({
                ...policy,
                maximum_weight: Number(event.target.value),
              })
            }
          />
        </label>
      </fieldset>
      <p className="notice">
        Observation is the default. A changed reply destination from a recurring
        address requires a current sensitive request and completed domain
        authentication. A protected-name mismatch also requires failed
        alignment. A new contact, frequency, a name change or unavailable checks
        alone never adds weight.
      </p>
      <p className="muted small">
        The content index retains the larger of this contribution and an
        overlapping Reply-To heuristic. This is not a percentage-point bonus, a
        spam probability or an automatic spam verdict. Independently calibrated
        fusion decisions keep their own inputs. Validate on labelled messages
        before enabling contributions; ordinary configuration review and
        activation on every MX still apply.
      </p>
    </section>
  );
}
export type IdentityCorrelationReport = {
  protocol: string;
  policy_sha256: string;
  mode: IdentityPolicy['mode'];
  status: string;
  content_available: boolean;
  recurrence_available: boolean;
  authentication: 'aligned' | 'failed' | 'unavailable';
  signals: string[];
  corroborated: boolean;
  proposed_weight: number;
  applied_weight: number;
};
const signals: Record<string, string> = {
  protected_identity_mismatch: 'Protected identity uses a different address',
  recurring_reply_changed:
    'Reply destination differs from authenticated history',
  recurring_name_changed: 'Displayed name differs from authenticated history',
  recurring_links_changed: 'Link destination is new in the available history',
  new_sensitive_request: 'Sensitive request is new in the available history',
  sensitive_request:
    'Current content requests sensitive information or an action',
  authentication_failed: 'SMTP-verified DMARC alignment failed',
};
export function IdentityCorrelationEvidence({
  report,
  retained,
}: {
  report: IdentityCorrelationReport;
  retained?: number | null;
}) {
  const available = ['complete', 'limited'].includes(report.status);
  const weight =
    typeof retained === 'number' && Number.isFinite(retained) ? retained : null;
  return (
    <section
      className="identity-evidence"
      aria-label="Corroborated identity changes"
    >
      <h3>
        <Fingerprint size={19} aria-hidden="true" />
        Corroborated identity changes
      </h3>
      <p>
        <strong>
          {!available
            ? 'Insufficient identity context'
            : report.corroborated
              ? 'Corroborated change observed'
              : 'No corroborated change'}
        </strong>{' '}
        ·{' '}
        {report.mode === 'observation'
          ? 'Observation only'
          : 'Bounded contribution policy'}
      </p>
      {available && report.signals.length > 0 && (
        <ul>
          {report.signals.map((signal) => (
            <li key={signal}>
              {signals[signal] ?? 'Additional identity observation'}
            </li>
          ))}
        </ul>
      )}
      {report.mode === 'observation' ? (
        <p>
          No score change.{' '}
          {report.corroborated
            ? `The proposed contribution was ${report.proposed_weight.toFixed(2)} log-odds units.`
            : 'No contribution was proposed.'}
        </p>
      ) : (
        <p>
          {weight === null
            ? 'No identity weight retained in the content ledger.'
            : `Content ledger retained ${weight.toFixed(2)} log-odds units after deduplication.`}{' '}
          The NoiseFence verdict and recipient delivery policy remain
          authoritative.
        </p>
      )}
      {!report.content_available && (
        <p>
          Current sensitive-request analysis was unavailable. Missing checks add
          no weight.
        </p>
      )}
      {!report.recurrence_available && (
        <p>
          No qualifying recurring-address baseline was available for this
          recipient.
        </p>
      )}
      <p className="muted small">
        Recurring delivery does not prove identity or create a safe-sender
        exemption. This evidence uses this recipient’s observations only; it
        does not establish reciprocal correspondence. Rspamd and LLM opinions
        are not inputs to this check.
      </p>
      <details>
        <summary>Recorded policy</summary>
        <dl>
          <dt>Protocol</dt>
          <dd>
            <code>{report.protocol}</code>
          </dd>
          <dt>Policy SHA-256</dt>
          <dd>
            <code>{report.policy_sha256}</code>
          </dd>
        </dl>
      </details>
    </section>
  );
}
