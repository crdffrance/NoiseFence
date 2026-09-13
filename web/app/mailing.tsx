'use client';

export type FeedbackCategory = 'spam' | 'publicity' | 'legitimate';
export type MailingPolicy = {
  include_newsletters: boolean;
  tag_subject: boolean;
};
export type MailingReport = {
  version: string;
  status: 'complete' | 'limited';
  verdict:
    | 'none'
    | 'promotion'
    | 'newsletter'
    | 'transactional'
    | 'conversation';
  reasons: { id: string; detail: string }[];
  elapsed_us: number;
};

export function MailingSettings({
  policy,
  actionsManaged = false,
  available,
  tagReady,
  mode,
  onChange,
}: {
  policy: MailingPolicy | null;
  actionsManaged?: boolean;
  available: boolean;
  tagReady: boolean;
  mode: 'observe' | 'tag' | 'enforce';
  onChange: (value: MailingPolicy | null) => void;
}) {
  return (
    <section className="panel mailing-settings">
      <h2>Marketing and newsletters</h2>
      <p className="muted">
        Marketing (PUB) identifies legitimate commercial mail and newsletters. Spam and malware classifications take priority.
      </p>
      <label
        className="toggle-row"
        aria-label="Distinguish Ads (PUB)"
      >
        <span>
          <strong>Distinguish Ads (PUB)</strong>
        </span>
        <input
          type="checkbox"
          role="switch"
          aria-checked={!!policy}
          checked={!!policy}
          disabled={!available}
          onChange={(e) =>
            onChange(
              e.target.checked
                ? {
                    include_newsletters: true,
                    tag_subject: mode === 'observe' || tagReady,
                  }
                : null,
            )
          }
        />
      </label>
      {!available && (
        <p className="notice">Module to install on the server.</p>
      )}
      {policy && (
        <>
          <label
            className="toggle-row"
            aria-label="Include editorial newsletters"
          >
            <span>
              <strong>Include editorial newsletters</strong>
              <small>
                Information letters are also classified as PUB.
              </small>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-checked={policy.include_newsletters}
              checked={policy.include_newsletters}
              onChange={(e) =>
                onChange({ ...policy, include_newsletters: e.target.checked })
              }
            />
          </label>
          {!actionsManaged && (
            <>
              <label
                className="toggle-row"
                aria-label="Add [PUB] to the subject in tagging mode"
              >
                <span>
                  <strong>Add [PUB] to the subject in tagging mode</strong>
                  <small>
                    Only one prefix is added. The body of the message is kept.
                  </small>
                </span>
                <input
                  type="checkbox"
                  role="switch"
                  aria-checked={policy.tag_subject}
                  checked={policy.tag_subject}
                  onChange={(e) =>
                    onChange({ ...policy, tag_subject: e.target.checked })
                  }
                />
              </label>
            </>
          )}
          <p className="muted small">
            Invoices, receipts, login codes and conversations are subject to exclusion criteria. Corrections are used to evaluate and improve detection.
          </p>
          {mode === 'observe' && (
            <p className="notice">
              Active observation: PUB appears in the console. No prefix is added to the delivered messages.
            </p>
          )}
          {!tagReady && (
            <p className="muted small">
              The [PUB] marking requires a Proton delivery validation specific to this prefix and a valid ARC configuration.
            </p>
          )}
        </>
      )}
    </section>
  );
}

export function MailingDetails({
  report,
  category,
  tagged,
}: {
  report: MailingReport;
  category: string;
  tagged: boolean;
}) {
  const verdicts = {
    none: "No corroborated marketing signals",
    promotion: "Commercial advertising",
    newsletter: 'Newsletter',
    transactional: "Transactional or service message",
    conversation: "Conversation or discussion list",
  };
  return (
    <section className="panel">
      <h2>Marketing and newsletters</h2>
      <p>
        <strong>
          {report.status === 'limited'
            ? "Limited categorization"
            : verdicts[report.verdict]}
        </strong>
      </p>
      {category === 'spam' && (
        <p className="notice">
          Spam classification takes priority over marketing signals.
        </p>
      )}
      {category === 'undetermined' && (
        <p className="notice">
          The safety analysis does not allow the PUB category to be retained.
        </p>
      )}
      {category === 'publicity' && (
        <p className="notice">
          {tagged
            ? "Prefix [PUB] added to delivery."
            : "Category PUB detected. No prefix [PUB] added to delivery."}
        </p>
      )}
      <ul className="reasons">
        {report.reasons.map((r) => (
          <li key={r.id}>{r.detail}</li>
        ))}
      </ul>
      <p className="muted small">
        Detector {report.version} · {(report.elapsed_us / 1000).toFixed(1)} ms · Independent of spam score.
      </p>
    </section>
  );
}
