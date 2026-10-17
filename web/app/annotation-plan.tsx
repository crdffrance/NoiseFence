export type AnnotationPlan = {
  schema: string;
  scope: string;
  may_activate: boolean;
  risk_ready: boolean;
  mail_kind_ready: boolean;
  risk_requires_mail_kind: boolean;
  partitions: {
    target: 'risk' | 'kind';
    partition: string;
    ready: boolean;
    minimum_additional_labelled_campaigns: number;
    unlabelled_or_uncertain_campaigns: number | null;
    minimum_new_campaigns_by_count: number | null;
    missing_classes: string[];
  }[];
};

export function AnnotationNextSteps({ value }: { value: AnnotationPlan }) {
  if (
    value.schema !== 'noisefence-annotation-plan-1' ||
    value.scope !== 'development_only' ||
    value.may_activate !== false ||
    value.risk_requires_mail_kind !== false
  ) {
    return (
      <p className="notice">
        This annotation plan is not supported. Run a new development report.
      </p>
    );
  }
  return (
    <section className="annotation-plan" aria-label="Next useful annotations">
      <h4>Next useful annotations</h4>
      <p className="notice">
        {value.risk_ready
          ? 'Risk fitting is ready for development. Independent qualification is still required.'
          : 'Risk fitting needs more independent labelled campaigns.'}{' '}
        Mail-type labels do not block risk fitting.
      </p>
      <p>
        Mail-type fitting:{' '}
        {value.mail_kind_ready ? 'ready for development' : 'not ready yet'}.
        Label whether you want a message separately from its type. Wanted
        advertising is wanted risk, not spam.
      </p>
      {(['risk', 'kind'] as const).map((target) => (
        <details key={target} open={target === 'risk' && !value.risk_ready}>
          <summary>
            {target === 'risk' ? 'Wanted / unwanted risk' : 'Mail type'} ·
            remaining evidence
          </summary>
          <div className="quality-table-scroll">
            <table className="quality-metrics">
              <caption>
                Development partitions · lower bounds, not collection quotas
              </caption>
              <thead>
                <tr>
                  <th>Partition</th>
                  <th>Additional labelled campaigns</th>
                  <th>Unlabelled or uncertain campaigns available</th>
                  <th>Missing classes</th>
                  <th>Next step</th>
                </tr>
              </thead>
              <tbody>
                {value.partitions
                  .filter((row) => row.target === target)
                  .map((row) => (
                    <tr key={row.partition}>
                      <th scope="row">{row.partition}</th>
                      <td data-label="Additional campaigns">
                        {row.minimum_additional_labelled_campaigns}
                      </td>
                      <td data-label="Still unlabelled">
                        {row.unlabelled_or_uncertain_campaigns ??
                          'Not measurable'}
                      </td>
                      <td data-label="Missing classes">
                        {row.missing_classes.join(', ') || 'None'}
                      </td>
                      <td data-label="Next step">
                        {row.ready
                          ? 'Ready for development'
                          : row.unlabelled_or_uncertain_campaigns == null
                            ? 'Collect a wider chronological window'
                            : row.unlabelled_or_uncertain_campaigns > 0
                              ? 'Review remaining unlabelled or uncertain campaigns'
                              : 'Collect more diverse traffic and freeze a new development window'}
                        {!row.ready &&
                          row.minimum_new_campaigns_by_count != null &&
                          row.minimum_new_campaigns_by_count > 0 && (
                            <small>
                              At least {row.minimum_new_campaigns_by_count} more
                              campaigns by count; class coverage is also
                              required.
                            </small>
                          )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </details>
      ))}
      <p className="muted small">
        Available campaigns have unknown labels; their count cannot guarantee
        the missing classes. Keep uncertain labels uncertain. Do not assign a
        label to fill a quota, relabel protected samples, or move messages
        between time partitions. New arrivals cannot fill an old fixed
        partition: collect a broader development window and freeze a new sample.
        Preserve the later independent holdout.
      </p>
      <p className="muted small">
        These counts exclude protected, conflicting and cross-period campaigns.
        Repeated messages do not add independent evidence. No model or delivery
        policy is activated here.
      </p>
    </section>
  );
}
