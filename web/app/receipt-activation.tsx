export type ReceiptEpoch = {
  sequence: number;
  revision: number;
  digest: string;
};

export function ReceiptActivation({ epoch }: { epoch?: ReceiptEpoch | null }) {
  const valid =
    epoch != null &&
    Number.isSafeInteger(epoch.sequence) &&
    epoch.sequence >= 0 &&
    Number.isSafeInteger(epoch.revision) &&
    epoch.revision >= 0 &&
    /^[a-f0-9]{64}$/.test(epoch.digest);
  return (
    <section aria-label="Recorded configuration identity">
      <h4>Configuration used for this message</h4>
      {!valid ? (
        <p className="diagnostic-muted">
          {epoch == null
            ? 'Not recorded for this message. Current settings are not substituted.'
            : 'Recorded identity cannot be displayed reliably. Current settings are not substituted.'}
        </p>
      ) : (
        <dl className="diagnostic-facts">
          <div>
            <dt>Configuration revision</dt>
            <dd>{epoch.revision}</dd>
          </div>
          <div>
            <dt>Activation sequence</dt>
            <dd>{epoch.sequence}</dd>
          </div>
          <div>
            <dt>Policy and model bundle SHA-256</dt>
            <dd>
              <code style={{ overflowWrap: 'anywhere' }}>{epoch.digest}</code>
            </dd>
          </div>
        </dl>
      )}
      <p className="diagnostic-muted">
        This identifies the configuration recorded at receipt. It does not
        certify detection quality.
      </p>
    </section>
  );
}
