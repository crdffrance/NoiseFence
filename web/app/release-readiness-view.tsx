export type Cohort = {
  messages: number;
  usable: number;
  wanted: number;
  unwanted: number;
  uncertain: number;
  unlabelled: number;
  usable_wanted: number;
  usable_unwanted: number;
  usable_uncertain: number;
  usable_unlabelled: number;
  exclusions: Record<string, number>;
};
export type Readiness = {
  schema: string;
  current_cohort: string;
  cohorts: Record<string, Cohort>;
  minimum_wanted_test_messages: number;
  minimum_unwanted_test_messages: number;
  qualification_required: boolean;
  blockers: string[];
};
const empty: Cohort = {
  messages: 0,
  usable: 0,
  wanted: 0,
  unwanted: 0,
  uncertain: 0,
  unlabelled: 0,
  usable_wanted: 0,
  usable_unwanted: 0,
  usable_uncertain: 0,
  usable_unlabelled: 0,
  exclusions: {},
};
function count(value: number) {
  return Number.isSafeInteger(value) && value >= 0
    ? value.toLocaleString('en-GB')
    : 'Not recorded';
}
const reasons: Record<string, string> = {
  missing_observation: 'Observation not recorded',
  invalid_observation: 'Invalid or oversized observation',
  unsupported_protocol: 'Incompatible feature protocol',
  non_smtp_observation: 'Not an original SMTP observation',
  incomplete_extraction: 'Content extraction incomplete',
  invalid_provenance: 'Detector provenance missing or invalid',
  invalid_features: 'Feature vector missing or invalid',
  missing_campaign_identity: 'Campaign identity missing or invalid',
};
export function ReadinessExclusions({
  exclusions,
}: {
  exclusions?: Record<string, number>;
}) {
  const entries = Object.entries(exclusions ?? {});
  if (!entries.length) return null;
  return (
    <details>
      <summary>Why some observations cannot be used</summary>
      <ul>
        {entries.map(([reason, total]) => (
          <li key={reason}>
            {Object.hasOwn(reasons, reason)
              ? reasons[reason]
              : 'Other unavailable observations'}
            : {count(total)}
          </li>
        ))}
      </ul>
      <p className="muted small">
        These messages and their annotations remain in the totals. Each excluded
        observation has one primary reason. Missing evidence does not mean
        legitimate mail.
      </p>
    </details>
  );
}
export function ReleaseReadinessView({
  report,
  error = '',
}: {
  report: Readiness | null;
  error?: string;
}) {
  const supported = report?.schema === 'noisefence-release-readiness-2';
  const known = supported && /^[a-f0-9]{64}$/.test(report.current_cohort);
  const current = known
    ? (report.cohorts[report.current_cohort] ?? empty)
    : null;
  const rows = current
    ? ([
        ['Wanted', current.wanted, current.usable_wanted],
        ['Unwanted', current.unwanted, current.usable_unwanted],
        ['Uncertain', current.uncertain, current.usable_uncertain],
        ['Unlabelled', current.unlabelled, current.usable_unlabelled],
      ] as const)
    : [];
  return (
    <section className="panel">
      <p className="eyebrow">RELEASE QUALIFICATION</p>
      <h2>Evidence before activation</h2>
      <p>
        A populated dashboard or a high score does not establish detection
        quality. Training, calibration and independent evaluation use separate
        campaigns.
      </p>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : !report ? (
        <p>Loading dataset readiness…</p>
      ) : !supported ? (
        <output>
          This server does not provide compatible dataset-readiness counts.
          Update the server before comparing usable annotations.
        </output>
      ) : (
        <>
          <div className="assessment-facts">
            <span className="status review">
              Independent qualification required
            </span>
            <span>
              Current detector cohort:{' '}
              {known ? report.current_cohort.slice(0, 12) : 'Not available'}
            </span>
          </div>
          {current ? (
            <>
              <p>
                {count(current.messages)} recorded messages ·{' '}
                {count(current.usable)} usable SMTP observations
              </p>
              <table>
                <caption>
                  Current cohort · your accessible messages from the last 30
                  days
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Human annotation</th>
                    <th scope="col">All retained</th>
                    <th scope="col">With usable observations</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(([label, all, usable]) => (
                    <tr key={label}>
                      <th scope="row">{label}</th>
                      <td>{count(all)}</td>
                      <td>{count(usable)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted small">
                Only wanted and unwanted annotations with usable observations
                count towards data preparation. Uncertain and unlabelled
                messages remain visible; they are not treated as legitimate
                examples.
              </p>
              <ReadinessExclusions exclusions={current.exclusions} />
            </>
          ) : (
            <p>
              The installed detector identity is unavailable. Current-cohort
              counts cannot be determined.
            </p>
          )}
          <p className="muted small">
            Usable means compatible, valid recorded features from an original
            SMTP session, completed content extraction and available campaign
            identifiers. External controls can still be unavailable; their
            recorded states remain part of the observations.
          </p>
          <p className="muted small">
            The promotion contract requires at least{' '}
            {count(report.minimum_wanted_test_messages)} wanted and{' '}
            {count(report.minimum_unwanted_test_messages)} unwanted test
            messages, confidence bounds, campaign independence, provenance and
            latency checks. These counts include development data, have not been
            deduplicated by campaign and do not establish membership in an
            independent test set. Other detector cohorts:{' '}
            {
              Object.keys(report.cohorts).filter(
                (k) => k !== report.current_cohort,
              ).length
            }
            .
          </p>
        </>
      )}
    </section>
  );
}
