export type ReferenceImpact = {
  source: string;
  labelled_comparisons: number;
  wanted_comparisons: number;
  new_false_positives: number;
  remaining_false_positives: number;
  resolved_false_positives: number;
};

export function PolicyReferenceImpact({ value }: { value?: ReferenceImpact }) {
  if (!value || value.source !== 'requesting_account_quality_annotations')
    return (
      <p className="muted small">
        Annotated reference comparison is unavailable. Re-run this preview on a
        compatible server.
      </p>
    );
  return (
    <section className="panel" aria-label="Known false-positive impact">
      <h3>Known false-positive impact</h3>
      {value.wanted_comparisons === 0 ? (
        <p>
          No wanted-message annotations are available in the complete
          comparisons. False-positive impact is unknown.
        </p>
      ) : (
        <>
          <p className={value.new_false_positives > 0 ? 'error' : undefined}>
            <strong>{value.new_false_positives} new false positives</strong> ·{' '}
            {value.remaining_false_positives} remain ·{' '}
            {value.resolved_false_positives} resolved.
          </p>
          <p>
            {value.wanted_comparisons} wanted messages among{' '}
            {value.labelled_comparisons} comparable messages with your risk
            annotations.
          </p>
        </>
      )}
      <p className="muted small">
        Compares the recorded recipient classification with the simulated
        classification. A wanted HAM or PUB becoming SPAM is a new false
        positive, even if observation mode still delivers it. Missing facts and
        unlabelled messages are excluded; zero observed errors does not
        establish safety for other mail. Rspamd and model opinions are not
        reference labels.
      </p>
    </section>
  );
}
