import { Fingerprint } from 'lucide-react';
import type { ProtectionReport } from './protection';
const labels: Record<string, string> = {
  protected_display_name: 'Familiar name, unexpected domain',
  lookalike_sender: 'Sender domain resembles a receiving domain',
  reply_domain_mismatch: 'Different reply destination',
};
export function IdentityEvidence({ report }: { report: ProtectionReport }) {
  const findings = report.findings.filter((f) => f.family === 'identity');
  return (
    <section className="identity-evidence" aria-label="Identity observations">
      <h3>
        <Fingerprint size={19} aria-hidden="true" />
        Identity observations
      </h3>
      <p>
        <strong>
          {findings.length
            ? `${findings.length} recorded ${findings.length === 1 ? 'finding' : 'findings'}`
            : 'No identity finding recorded'}
        </strong>{' '}
        ·{' '}
        {report.observation_only
          ? 'Observation only'
          : 'See recorded decision and policy'}
      </p>
      {findings.length > 0 && (
        <ul>
          {findings.map((finding, index) => (
            <li key={index}>
              <strong>{labels[finding.id] ?? 'Identity signal'}</strong>
              <p>{finding.detail}</p>
              <code>{finding.id}</code>
              {finding.sources.length > 0 && (
                <small className="muted">
                  {' '}
                  · Sources:{' '}
                  {finding.sources
                    .map((source) =>
                      source === 'headers' ? 'message headers' : source,
                    )
                    .join(', ')}
                </small>
              )}
            </li>
          ))}
        </ul>
      )}
      <p>
        Domain authentication:{' '}
        <strong>
          {report.authenticated_sender
            ? 'DMARC alignment confirmed'
            : 'DMARC alignment not confirmed'}
        </strong>
        . Alignment authenticates a domain, not the person writing the message.
      </p>
      <details>
        <summary>How to interpret this evidence</summary>
        <p>
          These findings provide context; they are not separate spam votes.
          Consult the NoiseFence verdict and delivery action above. A name
          mismatch can also involve a legitimate delegate or forwarding service.
        </p>
        <p>
          This report does not record individual identity-check availability. No
          finding does not prove that every identity check ran, or that a sender
          is safe. Employee-directory synchronization and a contact graph are
          not part of this report.
        </p>
      </details>
    </section>
  );
}

export type DirectoryIdentityReport = {
  catalog_sha256: string;
  relationships_available: boolean;
  sensitive_requests_available: boolean;
  observation: {
    protocol: string;
    status: string;
    observation_only: boolean;
    fresh_sources: number;
    applicable_sources: number;
    authentication: 'aligned' | 'failed' | 'unavailable';
    directory_address_match: boolean;
    ambiguous_identity: boolean;
    signals: string[];
    corroborated: boolean;
  };
};
const directorySignals: Record<string, [string, string]> = {
  protected_name_mismatch: [
    'Protected name, different address',
    'The displayed name matches a protected person, but the sending address is not one of their recorded addresses.',
  ],
  protected_group_mismatch: [
    'Protected group, different address',
    'The displayed name matches a protected group, but the sending address is not one of its recorded addresses.',
  ],
  known_address_authentication_failed: [
    'Known address, authentication failed',
    'The sending address appears in the directory, but the recorded SMTP authentication did not establish alignment.',
  ],
  known_contact_reply_changed: [
    'Reply destination changed',
    'The reply destination differs from the retained, qualified contact history.',
  ],
  known_contact_new_sensitive_request: [
    'Unusual sensitive request',
    'This kind of request is new in the retained, qualified contact history.',
  ],
  sensitive_request: [
    'Sensitive request',
    'A request involving sensitive information or an action was recorded.',
  ],
};
export function DirectoryIdentityEvidence({
  report,
}: {
  report: DirectoryIdentityReport;
}) {
  const observation = report.observation;
  const status: Record<string, string> = {
    complete: 'Directory checks completed',
    limited: 'Some directory sources unavailable',
    stale: 'Directory sources expired',
    not_configured: 'No directory assigned to this recipient',
    unavailable: 'Directory checks unavailable',
  };
  return (
    <section
      className="panel identity-evidence"
      aria-label="Directory identity observations"
    >
      <h3>
        <Fingerprint size={19} aria-hidden="true" />
        Directory identity
      </h3>
      <p>
        <strong>
          {status[observation.status] ?? 'Directory status not recorded'}
        </strong>{' '}
        ·{' '}
        {observation.observation_only
          ? 'Observation only'
          : 'See recorded policy'}
      </p>
      <p>
        {observation.fresh_sources} of {observation.applicable_sources}{' '}
        applicable sources were fresh at analysis time. This evidence belongs to
        the recipient of this message copy.
      </p>
      {observation.ambiguous_identity && (
        <p className="notice">
          Several directory identities could match. No unique person or group
          was established.
        </p>
      )}
      {observation.signals.length > 0 ? (
        <ul>
          {observation.signals.map((signal, index) => (
            <li key={`${signal}:${index}`}>
              <strong>
                {directorySignals[signal]?.[0] ?? 'Additional directory signal'}
              </strong>
              <p>
                {directorySignals[signal]?.[1] ??
                  'Consult the recorded technical identifier.'}
              </p>
              <code>{signal}</code>
            </li>
          ))}
        </ul>
      ) : (
        <p>
          No directory signal recorded. This does not verify the sender or
          establish that the message is safe.
        </p>
      )}
      <p>
        Domain authentication:{' '}
        <strong>
          {{
            aligned: 'DMARC alignment confirmed',
            failed: 'DMARC alignment failed',
            unavailable: 'Not established by trusted SMTP evidence',
          }[observation.authentication] ?? 'Not recorded'}
        </strong>
        .
      </p>
      <p>
        {observation.directory_address_match
          ? 'The address matches a directory entry. This does not prove who wrote the message.'
          : 'No unique address match was recorded.'}
      </p>
      <details>
        <summary>Scope, limitations and provenance</summary>
        <p>
          These directory observations do not independently decide the verdict or
          delivery action. The corroborated identity report, when present, records
          whether the configured policy retained a contribution. A legitimate delegate, a forwarded message or a compromised
          real account can require additional context.
        </p>
        {!report.relationships_available && (
          <p>
            The human-confirmed relationship baseline was unavailable to this
            directory check. Automatic correspondent memory, when enabled, has
            its own separate report.
          </p>
        )}
        {!report.sensitive_requests_available && (
          <p>
            Sensitive-request analysis was unavailable in this directory report.
          </p>
        )}
        <p>
          Checks are limited to the directory sources assigned to this
          recipient. No other recipient’s directory identities or addresses are
          included.
        </p>
        <dl>
          <dt>Directory snapshot SHA-256</dt>
          <dd>
            <code>{report.catalog_sha256}</code>
          </dd>
          <dt>Observation protocol</dt>
          <dd>
            <code>{observation.protocol}</code>
          </dd>
        </dl>
      </details>
    </section>
  );
}
