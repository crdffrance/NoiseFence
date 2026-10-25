import { useState } from 'react';
import { Repeat2 } from 'lucide-react';
import { ConfirmDialog } from './console-ui';
export type ContactLearningSettings = {
  enabled: boolean;
  retention_days: number;
  minimum_campaigns: number;
  minimum_days: number;
  learn_since: number;
};
export const defaultContactLearning: ContactLearningSettings = {
  enabled: true,
  retention_days: 30,
  minimum_campaigns: 5,
  minimum_days: 3,
  learn_since: 0,
};
export function contactLearningError(
  value?: ContactLearningSettings | null,
): string | null {
  if (!value) return null;
  if (
    !Number.isInteger(value.retention_days) ||
    value.retention_days < 7 ||
    value.retention_days > 30
  )
    return 'Choose a memory window between 7 and 30 days.';
  if (
    !Number.isInteger(value.minimum_campaigns) ||
    value.minimum_campaigns < 5 ||
    value.minimum_campaigns > Math.min(60, 2 * value.retention_days)
  )
    return 'Choose at least 5 campaigns, within the two-per-day memory capacity.';
  if (
    !Number.isInteger(value.minimum_days) ||
    value.minimum_days < 3 ||
    value.minimum_days > Math.min(14, value.retention_days)
  )
    return 'Choose between 3 and 14 observation days within the memory window.';
  if (!Number.isSafeInteger(value.learn_since) || value.learn_since < 0)
    return 'The observation start time is invalid.';
  return null;
}
export function ContactLearningSettingsEditor({
  value,
  disabled,
  onChange,
}: {
  value?: ContactLearningSettings | null;
  disabled: boolean;
  onChange: (value: ContactLearningSettings) => void;
}) {
  const [reset, setReset] = useState(false);
  const settings = value ?? { ...defaultContactLearning, enabled: false };
  return (
    <section
      className="card contact-learning-settings"
      aria-label="Automatic correspondent memory"
    >
      <div className="identity-heading">
        <Repeat2 size={22} aria-hidden="true" />
        <div>
          <h2>Automatic correspondent memory</h2>
          <p>
            Learn recurring, authenticated exchanges separately for every
            recipient.
          </p>
        </div>
      </div>
      <p className="notice">
        Observation only. Regular contact does not mean safe sender. This memory
        never bypasses phishing checks, changes a verdict or creates training
        labels.
      </p>
      <fieldset disabled={disabled} className="contact-learning-fields">
        <legend>Learning policy</legend>
        <label className="check">
          <input
            type="checkbox"
            checked={settings.enabled}
            onChange={(event) =>
              onChange({ ...settings, enabled: event.target.checked })
            }
          />
          Learn from accepted messages
        </label>
        <div className="contact-learning-grid">
          <label>
            Memory window (days)
            <input
              type="number"
              min={7}
              max={30}
              value={settings.retention_days}
              onChange={(event) =>
                onChange({
                  ...settings,
                  retention_days: Number(event.target.value),
                })
              }
            />
          </label>
          <label>
            Minimum distinct campaigns
            <input
              type="number"
              min={5}
              max={Math.min(60, 2 * settings.retention_days)}
              value={settings.minimum_campaigns}
              onChange={(event) =>
                onChange({
                  ...settings,
                  minimum_campaigns: Number(event.target.value),
                })
              }
            />
          </label>
          <label>
            Minimum observation days
            <input
              type="number"
              min={3}
              max={Math.min(14, settings.retention_days)}
              value={settings.minimum_days}
              onChange={(event) =>
                onChange({
                  ...settings,
                  minimum_days: Number(event.target.value),
                })
              }
            />
          </label>
        </div>
        <p className="muted small">
          Only SMTP-verified DKIM alignment qualifies for learning. Messages
          that fail alignment can still be compared with prior authenticated
          history. Repeated copies count once; at most two distinct campaigns
          count per day. A recorded human spam correction prevents
          regular-contact status while it remains in the memory window.
        </p>
        <button
          type="button"
          className="secondary"
          onClick={() => setReset(true)}
        >
          Start a new observation window…
        </button>
        {settings.learn_since > 0 && (
          <p className="muted small">
            History before{' '}
            {new Date(settings.learn_since * 1000).toLocaleString('en-GB')} is
            excluded.
          </p>
        )}
      </fieldset>
      <p className="muted small">
        Changes take effect after the configuration review and activation on
        every MX. Disabling stops collection and comparison. Existing message
        metadata follows its retention policy; restarting a window does not
        delete messages.
      </p>
      {reset && (
        <ConfirmDialog
          title="Start a new observation window?"
          confirmLabel="Update draft"
          busy={false}
          onCancel={() => setReset(false)}
          onConfirm={() => {
            onChange({
              ...settings,
              learn_since: Math.floor(Date.now() / 1000),
            });
            setReset(false);
          }}
        >
          <p>
            Future comparisons will exclude earlier observations after this
            draft is applied. Messages, human corrections and model training
            data are preserved.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
export type ContactLearningReport = {
  learning_eligible?: boolean | null;
  dkim_alignment?: 'verified' | 'not_verified' | 'unavailable' | null;
  status: string;
  observation_only: boolean;
  regular: boolean;
  campaigns: number;
  observed_days: number;
  last_seen_at: number | null;
  retention_days: number;
  minimum_campaigns: number;
  minimum_days: number;
  blocked_by_feedback: boolean;
  content_comparison_available: boolean;
  changes: string[];
};
const statuses: Record<string, string> = {
  regular: 'Recurring address in authenticated history',
  learning: 'Building contact history',
  human_rejected: 'Prior human spam correction',
  limited: 'History capacity reached',
  unavailable: 'Contact history unavailable',
  ineligible: 'Message not eligible for automatic learning',
};
const changes: Record<string, string> = {
  dkim_alignment: 'DKIM alignment differs from the authenticated history',
  display_name: 'Display name differs from the recurring pattern',
  reply_destination: 'Reply destination differs from the recurring pattern',
  link_domain: 'Link domain is new or not yet established',
  sensitive_request: 'Sensitive request is new or not yet established',
};
export function ContactLearningEvidence({
  report,
}: {
  report: ContactLearningReport;
}) {
  const available = ['regular', 'learning', 'human_rejected'].includes(
    report.status,
  );
  return (
    <section className="identity-evidence" aria-label="Correspondent memory">
      <h3>
        <Repeat2 size={19} aria-hidden="true" />
        Correspondent memory
      </h3>
      <p>
        <strong>
          {statuses[report.status] ?? 'Contact history unavailable'}
        </strong>{' '}
        · Observation only
      </p>
      {available && (
        <p>
          {report.campaigns} distinct campaigns on {report.observed_days} days,
          within a {report.retention_days}-day window. Regularity requires at
          least {report.minimum_campaigns} campaigns on {report.minimum_days}{' '}
          days.
        </p>
      )}
      {report.dkim_alignment === 'not_verified' && (
        <p className="notice">
          This message does not have verified DKIM alignment. Historical
          recurrence matches its claimed address, not the identity of its
          writer. SPF or forwarding may explain the difference; it is not a spam
          verdict.
        </p>
      )}
      {report.dkim_alignment === 'unavailable' && (
        <p className="muted small">
          Current DKIM alignment could not be established. Missing
          authentication is not recorded as a failed check or a change in the
          contact pattern.
        </p>
      )}
      {report.learning_eligible === false && (
        <p>This message is excluded from automatic learning.</p>
      )}
      {report.status === 'ineligible' && (
        <p>
          Learning requires a single valid From address, complete text features
          and DKIM alignment verified by this gateway. Imported authentication
          headers, bounces and known malware cannot establish a contact.
        </p>
      )}
      {report.status === 'unavailable' && (
        <p>
          The selected history source was missing, stale or could not be read
          within its time budget. This is not evidence that the sender is new.
        </p>
      )}
      {report.status === 'limited' && (
        <p>
          The bounded history is incomplete. Regularity and change detection
          were not inferred from a partial sample.
        </p>
      )}
      {report.blocked_by_feedback && (
        <p>
          A retained human spam correction prevents regular-contact status.
          Frequent delivery does not override that correction.
        </p>
      )}
      {available && report.last_seen_at && (
        <p className="muted small">
          Latest qualifying observation:{' '}
          {new Date(report.last_seen_at * 1000).toLocaleString('en-GB')}
        </p>
      )}
      {report.regular && report.changes.length > 0 && (
        <ul>
          {report.changes.map((change) => (
            <li key={change}>
              {changes[change] ?? 'Unrecognized context change'}
            </li>
          ))}
        </ul>
      )}
      {report.regular && !report.changes.length && (
        <p>No change was observed in the available comparisons.</p>
      )}
      {!report.content_comparison_available && (
        <p className="muted small">
          Link and sensitive-request comparison is unavailable or lacks
          sufficient complete history.
        </p>
      )}
      <p className="muted small">
        This recipient’s inbound history only. Frequency is not identity
        verification or a safe-sender exemption. A regular sender can be
        compromised; NoiseFence keeps its independent verdict.
      </p>
    </section>
  );
}
